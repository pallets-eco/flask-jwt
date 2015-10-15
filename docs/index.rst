Flask-JWT
=========

.. currentmodule:: flask_jwt

Add basic JWT features to your `Flask`_ application.


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

    from flask import Flask
    from flask_jwt import JWT, jwt_required, current_identity
    from werkzeug.security import safe_str_cmp

    class User(object):
        def __init__(self, id, username, password):
            self.id = id
            self.username = username
            self.password = password

        def __str__(self):
            return "User(id='%s')" % self.id

    users = [
        User(1, 'user1', 'abcxyz'),
        User(2, 'user2', 'abcxyz'),
    ]

    username_table = {u.username: u for u in users}
    userid_table = {u.id: u for u in users}

    def authenticate(username, password):
        user = username_table.get(username, None)
        if user and safe_str_cmp(user.password.encode('utf-8'), password.encode('utf-8')):
            return user

    def identity(payload):
        user_id = payload['identity']
        return userid_table.get(user_id, None)

    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'super-secret'

    jwt = JWT(app, authenticate, identity)

    @app.route('/protected')
    @jwt_required()
    def protected():
        return '%s' % current_identity

    if __name__ == '__main__':
        app.run()



To get a token make a request to the auth resource::

    POST /auth HTTP/1.1
    Host: localhost:5000
    Content-Type: application/json

    {
        "username": "joe",
        "password": "pass"
    }

The response should look similar to::

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6MSwiaWF0IjoxNDQ0OTE3NjQwLCJuYmYiOjE0NDQ5MTc2NDAsImV4cCI6MTQ0NDkxNzk0MH0.KPmI6WSjRjlpzecPvs3q_T3cJQvAgJvaQAPtk1abC_E"
    }

This token can then be used to make requests against protected endpoints::

    GET /protected HTTP/1.1
    Authorization: JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6MSwiaWF0IjoxNDQ0OTE3NjQwLCJuYmYiOjE0NDQ5MTc2NDAsImV4cCI6MTQ0NDkxNzk0MH0.KPmI6WSjRjlpzecPvs3q_T3cJQvAgJvaQAPtk1abC_E


Within a function decorated by `jwt_required()`, you can use the
`current_identity` proxy to access the user whose token was passed into this
request context.


Configuration Options
---------------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

========================== =====================================================
``JWT_DEFAULT_REALM``      The default realm. Defaults to ``Login Required``
``JWT_AUTH_URL_RULE``      The authentication endpoint URL. Defaults to
                           ``/auth``.
``JWT_AUTH_ENDPOINT``      The authentication endpoint name. Defaults to
                           ``jwt``.
``JWT_AUTH_USERNAME_KEY``  The username key in the authentication request
                           payload. Defaults to ``username``.
``JWT_AUTH_PASSWORD_KEY``  The password key in the authentication request
                           payload. Defaults to ``password``.
``JWT_ALGORITHM``          The token algorithm. Defaults to ``HS256``
``JWT_LEEWAY``             The amount of leeway given when decoding access
                           tokens specified as an integer of seconds or a
                           ``datetime.timedelta`` instance. Defaults to
                           ``timedelta(seconds=10)``.
``JWT_VERIFY``             Flag indicating if all tokens should be verified.
                           Defaults to ``True``. It is not recommended to
                           change this value.
``JWT_AUTH_HEADER_PREFIX`` The Authorization header value prefix. Defaults to
                           ``JWT`` as to not conflict with OAuth2 Bearer
                           tokens. This is not a case sensitive value.
``JWT_VERIFY_EXPIRATION``  Flag indicating if all tokens should verify their
                           expiration time. Defaults to ``True``. It is not
                           recommended to change this value.
``JWT_LEEWAY``             A token expiration leeway value. Defaults to ``0``.
``JWT_EXPIRATION_DELTA``   A ``datetime.timedelta`` value indicating how long
                           tokens are valid for. This value is added to the
                           ``iat`` (issued at) claim. Defaults to
                           ``timedelta(seconds=300)``
``JWT_NOT_BEFORE_DELTA``   A ``datetime.timedelta`` value indicating a relative
                           time from the ``iat`` (issued at) claim that the
                           token can begin to be used. This value is added to
                           the ``iat`` (issued at) claim. Defaults to
                           ``timedelta(seconds=0)``
``JWT_VERIFY_CLAIMS``      A list of claims to verify when decoding tokens.
                           Defaults to ``['signature', 'exp', 'nbf', 'iat']``.
``JWT_REQUIRED_CLAIMS``    A list of claims that are required in a token to be
                           considered valid. Defaults to
                           ``['exp', 'iat', 'nbf']``
========================== =====================================================

API
---

.. data:: current_identity

   A proxy for the current identity. It will only be set in the context of
   function decorated by `jwt_required()`.

.. module:: flask_jwt

.. autoclass:: JWT
    :members:

.. autofunction:: jwt_required


Changelog
---------
.. toctree::
   :maxdepth: 2

   changelog

.. _Flask: http://flask.pocoo.org
.. _GitHub: http://github.com/mattupstate/flask-jwt
