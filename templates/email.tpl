<html>
  <head></head>
  <body>
    <p>Hello, {{ username }}!</p>
    <br>
    <p>Someone (we hope it was you) requested to reset password on <a href="{{ service_url }}">{{ service_url }}</a>.</p>
    <p>Your confirmation token is: {{ token }}</p>
    <p>To proceed with the password reset procedure, please go to <a href="{{ service_url }}/reset/confirm">{{ service_url }}/reset/confirm</a> and provide this token.</p>
  </body>
</html>
