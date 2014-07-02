Flask-JWT
=========
.. currentmodule:: flask.ext.jwt

Add basic JWT authentication features to your `Flask`_ application.


Links
-----

* `documentation <http://packages.python.org/Flask-JWT/>`_
* `source <http://github.com/mattupstate/flask-jwt>`_
* :doc:`changelog </changelog>`


Installation
------------

Install with **pip** or **easy_install**::

    pip install Flask-JWT

or download the latest version from version control::

    git clone https://github.com/mattupstate/flask-jwt.git ./flask-jwt
    pip install ./flask-jwt


Quickstart
----------

Minimum viable application configuration:

.. code-block:: python

    # app.py
    from flask import Flask
    from flask_jwt import JWT, jwt_required

    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'super-secret'

    jwt = JWT(app)

    class User(object):
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    @jwt.authentication_handler
    def authenticate(username, password):
        if username == 'joe' and password == 'pass':
            return User(id=1, username='joe')

    @jwt.user_handler
    def load_user(payload):
        if payload['user_id'] == 1:
            return User(id=1, username='joe')

    @app.route('/protected')
    @jwt_required()
    def protected():
        return 'Success!'

    if __name__ == '__main__':
        app.run()

To get a token make the request::

    POST /auth
    Content-Type: application/json

    {
        "username": "joe",
        "password": "pass"
    }

The response should look similar to (just with a real token)::

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "token": "<jwt-token>"
    }

This token can then be used to make requests against protected endpoints::

    GET /protected
    Authorization: Bearer <jwt-token>

    HTTP/1.1 200 OK

    Success!

Within a function decorated by `jwt_required()`, you can use the `current_user`
proxy to access the user whose token was passed into this request context.


Configuration Options
---------------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

========================= ======================================================
``JWT_DEFAULT_REALM``     The default realm. Defaults to ``Login Required``
``JWT_AUTH_URL_RULE``     The authentication endpoint URL. Defaults to
                          ``/auth``.
``JWT_AUTH_ENDPOINT``     The authentication endpoint name. Defaults to
                          ``jwt``.
``JWT_ALGORITHM``         The token algorithm. Defaults to ``HS256``
``JWT_VERIFY``            Flag indicating if all tokens should be verified.
                          Defaults to ``True``. It is not recommended to change
                          this value.
``JWT_VERIFY_EXPIRATION`` Flag indicating if all tokens should verify their
                          expiration time. Defaults to ``True``. It is not
                          recommended to change this value.
``JWT_LEEWAY``            A token expiration leeway value. Defaults to ``0``.
``JWT_EXPIRATION_DELTA``  A timedelta value indicating how long tokens are valid
                          for. Defaults to ``timedelta(seconds=300)``
========================= ======================================================

API
---

.. data:: current_user

   A proxy for the current user. It will only be set in the context of function
   decorated by `jwt_required()` or after you call `verify_jwt()` manually within
   a view.

.. module:: flask_jwt

.. autoclass:: JWT
   :members: authentication_handler, user_handler, error_handler, payload_handler, encode_handler, decode_handler

.. autofunction:: jwt_required

.. autofunction:: verify_jwt


Changelog
---------
.. toctree::
   :maxdepth: 2

   changelog

.. _Flask: http://flask.pocoo.org
.. _GitHub: http://github.com/mattupstate/flask-jwt
