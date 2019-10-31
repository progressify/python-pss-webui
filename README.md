# python-pss-webui

*python-pss-webui* is yet another password self service WebUI for LDAP/AD. It was originally forked from [https://github.com/jirutka/ldap-passwd-webui](jirutka/ldap-passwd-webui), which is a nice small bottle app. It was extended with several features, which include:

* Password reset capability without need for database or LDAP schema extension.
* Password quality checker, including dictionary check.

# Running
Running as a standalone app is as simple as
```
python3 python-pss-webui.py
```
However it is recommened to use WSGI server in front.
