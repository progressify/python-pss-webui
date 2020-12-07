#!/usr/bin/env python3

import logging
import time
from os import environ, path
from base64 import b32encode, b32decode
from hashlib import sha256
from smtplib import SMTP
from email.mime.text import MIMEText
import bottle
from bottle import get, post, static_file, request, route, template
from bottle import SimpleTemplate
from configparser import ConfigParser
from ldap3 import Connection, Server
from ldap3 import SIMPLE, SUBTREE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPBindError, LDAPConstraintViolationResult, \
    LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError, \
    LDAPSocketOpenError, LDAPExceptionError


BASE_DIR = path.dirname(__file__)
LOG = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(levelname)s: %(message)s'
VERSION = '0.1.1'


@get('/')
def get_index():
    return template('templates/index')


@post('/')
def post_index():
    form = request.forms.getunicode

    def error(msg):
        return template('templates/index', username=form('username'), alerts=[('error', msg)])

    if form('new-password') != form('confirm-password'):
        return error("Password doesn't match the confirmation!")

    if not password_is_strong(form('new-password')):
        return error("Password did not pass quality checks!")

    try:
        change_password(form('username'), form('old-password'), form('new-password'))
    except Error as e:
        LOG.warning("Unsuccessful attempt to change password for %s: %s" % (form('username'), e))
        return error(str(e))

    LOG.info("Password successfully changed for: %s" % form('username'))

    return template('templates/index', alerts=[('success', "Password has been changed")])


@get('/reset')
def get_reset():
    return template('templates/reset')


@post('/reset')
def post_reset():
    form = request.forms.getunicode

    def error(msg):
        return template('templates/reset', username=form('username'), alerts=[('error', msg)])

    try:
        send_confirmation_code(CONF['ldap'], form('username'))
        LOG.info(f"E-mail has been sent for {form('username')}")
        return template('templates/reset', alerts=[('success', "Confirmation token has been sent to your mailbox")])
    except Exception as e:
        LOG.error(f'Failed to send e-mail: {e}')
        return error("Oops... something went wrong!")


@get('/reset/confirm')
def get_reset_confirm():
    return template('templates/reset_confirm')


@post('/reset/confirm')
def post_reset_confirm():
    form = request.forms.getunicode

    def error(msg):
        return template('templates/reset_confirm', username=form('username'), alerts=[('error', msg)])

    if form('new-password') != form('confirm-password'):
        return error("Password doesn't match the confirmation!")

    if not password_is_strong(form('new-password')):
        return error("Password did not pass quality checks!")

    if not token_is_valid(form('username'), form('token')):
        return error("Confirmation code is not valid or expired!")

    try:
        reset_password(form('username'), form('new-password'))
    except Error as e:
        LOG.warning("Unsuccessful attempt to change password for %s: %s" % (form('username'), e))
        return error(str(e))

    LOG.info("Password successfully changed for: %s" % form('username'))

    return template('templates/reset_confirm', alerts=[('success', "Password has been changed")])


@route('/static/<filename>', name='static')
def serve_static(filename):
    return static_file(filename, root=path.join(BASE_DIR, 'static'))


def connect_ldap(conf, **kwargs):
    server = Server(host=conf['host'],
                    port=conf.getint('port', None),
                    use_ssl=conf.getboolean('use_ssl', False),
                    connect_timeout=5)

    return Connection(server, raise_exceptions=True, **kwargs)


def change_password(username, old_pass, new_pass):
    conf = CONF['ldap']
    LOG.debug(f"Resetting password in for {username}")

    try:
        if conf.get('type') == 'ad':
            change_password_ad(conf, username, old_pass, new_pass)
        else:
            change_password_ldap(conf, username, old_pass, new_pass)

    except (LDAPBindError, LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError):
        raise Error('Username or password is incorrect!')

    except LDAPConstraintViolationResult as e:
        # Extract useful part of the error message (for Samba 4 / AD).
        msg = e.message.split('check_password_restrictions: ')[-1].capitalize()
        raise Error(msg)

    except LDAPSocketOpenError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Unable to connect to the remote server.')

    except LDAPExceptionError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Encountered an unexpected error while communicating with the remote server.')


def change_password_ldap(conf, username, old_pass, new_pass):
    user_dn = find_user_attribute(conf, username, 'distinguishedName')

    # Note: raises LDAPUserNameIsMandatoryError when user_dn is None.
    with connect_ldap(conf, authentication=SIMPLE, user=user_dn, password=old_pass) as c:
        c.bind()
        c.extend.standard.modify_password(user_dn, old_pass, new_pass)


def change_password_ad(conf, username, old_pass, new_pass):
    user = username + '@' + conf['ad_domain']
    user_dn = find_user_attribute(conf, username, 'distinguishedName')

    with connect_ldap(conf, authentication=SIMPLE, user=user, password=old_pass) as c:
        c.bind()
        c.extend.microsoft.modify_password(user_dn, new_pass, old_pass)


def reset_password(username, new_pass):
    conf = CONF['ldap']
    LOG.debug(f"Resetting password in for {username}")

    try:
        if conf.get('type') == 'ad':
            reset_password_ad(conf, username, new_pass)
        else:
            reset_password_ldap(conf, username, new_pass)

    except (LDAPBindError, LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError):
        raise Error('Username or password is incorrect!')

    except LDAPConstraintViolationResult as e:
        # Extract useful part of the error message (for Samba 4 / AD).
        msg = e.message.split('check_password_restrictions: ')[-1].capitalize()
        raise Error(msg)

    except LDAPSocketOpenError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Unable to connect to the remote server.')

    except LDAPExceptionError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Encountered an unexpected error while communicating with the remote server.')

    except Exception as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Oops... something went wrong!')


def reset_password_ldap(conf, username, new_pass):
    user_dn = find_user_attribute(conf, username, 'distinguishedName')
    manager_user_dn = find_user_attribute(conf, conf['password_manager_uid'], 'distinguishedName')
    manager_password = conf['password_manager_password']

    # Note: raises LDAPUserNameIsMandatoryError when user_dn is None.
    with connect_ldap(conf, authentication=SIMPLE, user=manager_user_dn, password=manager_password) as c:
        c.bind()
        c.extend.standard.modify_password(user_dn, '', new_pass)


def reset_password_ad(conf, username, new_pass):
    if 'ad_domain' in conf:
        manager_user = conf['password_manager_uid'] + '@' + conf['ad_domain']
    else:
        manager_user = conf['password_manager_uid']
    manager_password = conf['password_manager_password']
    user_dn = find_user_attribute(conf, username, 'distinguishedName')

    with connect_ldap(conf, authentication=SIMPLE, user=manager_user, password=manager_password) as c:
        c.bind()
        c.extend.microsoft.modify_password(user_dn, new_pass)


def find_user_attribute(conf, uid, attribute):
    if 'ad_domain' in conf:
        manager_user = conf['password_manager_uid'] + '@' + conf['ad_domain']
    else:
        manager_user = conf['password_manager_uid']
    manager_password = conf['password_manager_password']
    search_filter = conf['search_filter'].replace('{uid}', uid)

    try:
        with connect_ldap(conf, authentication=SIMPLE, user=manager_user, password=manager_password) as c:
            c.bind()
            c.search(conf['base'], "(%s)" % search_filter, SUBTREE, attributes=ALL_ATTRIBUTES)

            if len(c.response) < 1:
                LOG.error(f'User {uid} not found.')
                return None

            if attribute in c.response[0]['attributes']:
                return c.response[0]['attributes'][attribute]
            elif 'dn' in c.response[0]:
                return c.response[0]['dn']
            else:
                return None

    except (LDAPBindError, LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError):
        raise Error('Username or password is incorrect!')

    except LDAPConstraintViolationResult as e:
        # Extract useful part of the error message (for Samba 4 / AD).
        msg = e.message.split('check_password_restrictions: ')[-1].capitalize()
        raise Error(msg)

    except LDAPSocketOpenError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Unable to connect to the remote server.')

    except LDAPExceptionError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Encountered an unexpected error while communicating with the remote server.')

    except Exception as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Oops... something went wrong!')


def read_config():
    config = ConfigParser()
    config.read([path.join(BASE_DIR, 'settings.ini'), environ.get('CONF_FILE', '')])

    return config


# this returns True if password is strong (based on a set of quality checks)
def password_is_strong(password):
    if 'password_quality' in CONF.keys():
        conf = CONF['password_quality']
    else:
        LOG.warning("Password quality checker is disabled.")
        return True
    # password length check
    if len(password) < conf.getint('min_length', 8):
        LOG.debug("Password is weak because it is too short.")
        return False
    # number of password complexity checks
    if conf.getboolean('mixed_case_required', False):
        if password.islower() or password.isupper() or password.isdigit():
            LOG.debug("Password is weak because it is not mixed case.")
            return False
    if conf.getboolean('digit_required', False):
        if not any([digit in password for digit in '0123456789']):
            LOG.debug("Password is weak because it contains no digits.")
            return False
    if conf.getboolean('special_required', False):
        if not any([special in password for special in '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~']):
            LOG.debug("Password is weak because it contains no special characters.")
            return False
    # password dictionary check
    if conf.getboolean('dictionary_check_enabled', False):
        with open(conf['dictionary_file'], 'rt') as dictionary_file:
            for line in dictionary_file:
                if line.isspace():
                    continue
                pattern = line.rstrip().lower()
                if pattern in password.lower():
                    LOG.debug("Password is weak because its part is present in dictionary.")
                    return False
    # return True if not yet returned (password is strong)
    LOG.info("Password quality check passed.")
    return True


# Generate token for e-mail confirmation before password reset.
# A token is a base32-encoded hash of some salted string,
# which changes over time to provide expiration mechanism. 
def generate_token(username):
    # hashed string consists of username and several salts.
    # constant salt:
    salt1 = b32decode(CONF['password_reset']['salt'])
    # date/hour-dependent salt:
    salt2 = time.strftime('%Y-%m-%dT%H').encode('utf-8')
    # pwdLastSet dependent salt:
    try:
        salt3 = find_user_attribute(CONF['ldap'], username, 'pwdLastSet').strftime('%s').encode('utf-8')
    except Exception as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        return ''

    sha256sum = sha256(username.encode('utf-8') + salt1 + salt2 + salt3).digest()
    return b32encode(sha256sum).decode('utf-8')[:12]


# Retruns True if token is valid for the user
def token_is_valid(username, token):
    # stupid brute-force protection
    time.sleep(1.0)

    try:
        if token == generate_token(username):
            return True
        else:
            LOG.warning(f'Token provided for user {username} is not valid or expired.')
            return False
    except Exception as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        return False


def send_confirmation_code(conf, username):
    # get user e-mail addess from LDAP attributes.
    user_email = find_user_attribute(conf, username, 'mail')
    if not user_email:
        raise Error(f'Cannot find e-mail address for user {username}.')

    # generate token.
    try:
        token = generate_token(username)
    except Exception as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise e
        
    # prepare e-mail message.
    msg_body = template('templates/email', username=username, token=token)
    msg = MIMEText(msg_body, 'html', 'utf-8')
    msg['Subject'] = CONF['password_reset']['mail_subject']
    msg['From'] = CONF['password_reset']['smtp_from']
    msg['To'] = user_email

    # send the message via SMTP server.
    try:
        with SMTP(CONF['password_reset']['smtp_relay']) as s:
            s.sendmail(msg['From'], [msg['To']], msg.as_string())
            LOG.info(f"Email successfully sent to {msg['To']}.")
    except Exception as e:
        raise Error(f"Email cannot be sent to {msg['To']}: {e}")

    return True


class Error(Exception):
    pass


if environ.get('DEBUG'):
    bottle.debug(True)

# Set up logging.
logging.basicConfig(format=LOG_FORMAT)
LOG.setLevel(logging.INFO)
LOG.info("Starting PSS %s" % VERSION)

CONF = read_config()

bottle.TEMPLATE_PATH = [BASE_DIR]

# Set default attributes to pass into templates.
SimpleTemplate.defaults = dict(CONF['general'])
SimpleTemplate.defaults['url'] = bottle.url


# Run bottle internal server when invoked directly (mainly for development).
if __name__ == '__main__':
    bottle.run(**CONF['server'])
# Run bottle in application mode (in production under uWSGI server).
else:
    application = bottle.default_app()
