# -*- coding: utf-8 -*-
"""
    flask_jwt
    ~~~~~~~~~

    Flask-JWT module
"""

from collections import OrderedDict
from datetime import datetime, timedelta
from functools import wraps

import jwt

from flask import current_app, request, jsonify, _request_ctx_stack
from flask.views import MethodView
from werkzeug.local import LocalProxy

__version__ = '0.1.0'

current_user = LocalProxy(lambda: _request_ctx_stack.top.current_user)

_jwt = LocalProxy(lambda: current_app.extensions['jwt'])


def _default_payload_handler(user):
    return {
        'user_id': user.id,
        'exp': datetime.utcnow() + current_app.config['JWT_EXPIRATION_DELTA']
    }


def _default_encode_handler(payload):
    return jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        current_app.config['JWT_ALGORITHM']
    ).decode('utf-8')


def _default_decode_handler(token):
    return jwt.decode(
        token,
        current_app.config['JWT_SECRET_KEY'],
        current_app.config['JWT_VERIFY'],
        current_app.config['JWT_VERIFY_EXPIRATION'],
        current_app.config['JWT_LEEWAY']
    )

CONFIG_DEFAULTS = {
    'JWT_DEFAULT_REALM': 'Login Required',
    'JWT_AUTH_URL_RULE': '/auth',
    'JWT_AUTH_ENDPOINT': 'jwt',
    'JWT_ENCODE_HANDLER': _default_encode_handler,
    'JWT_DECODE_HANDLER': _default_decode_handler,
    'JWT_PAYLOAD_HANDLER': _default_payload_handler,
    'JWT_ALGORITHM': 'HS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': timedelta(seconds=300)
}


def jwt_required(realm=None):
    """View decorator that requires a valid JWT token to be present in the request

    :param realm: an optional realm
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt(realm)
            return fn(*args, **kwargs)
        return decorator
    return wrapper


class JWTError(Exception):
    def __init__(self, error, description, status_code=400, headers=None):
        self.error = error
        self.description = description
        self.status_code = status_code
        self.headers = headers


def verify_jwt(realm=None):
    realm = realm or current_app.config['JWT_DEFAULT_REALM']
    auth = request.headers.get('Authorization', None)

    if auth is None:
        raise JWTError('Authorization Required', 'Authorization header was missing', 401, {
            'WWW-Authenticate': 'JWT realm="%s"' % realm
        })

    parts = auth.split()

    if parts[0].lower() != 'bearer':
        raise JWTError('Invalid JWT header', 'Unsupported authorization type')
    elif len(parts) == 1:
        raise JWTError('Invalid JWT header', 'Token missing')
    elif len(parts) > 2:
        raise JWTError('Invalid JWT header', 'Token contains spaces')

    try:
        handler = current_app.config['JWT_DECODE_HANDLER']
        payload = handler(parts[1])
    except jwt.ExpiredSignature:
        raise JWTError('Invalid JWT', 'Token is expired')
    except jwt.DecodeError:
        raise JWTError('Invalid JWT', 'Token is undecipherable')

    _request_ctx_stack.top.current_user = user = _jwt.user_callback(payload)

    if user is None:
        raise JWTError('Invalid JWT', 'User does not exist')


class JWTAuthView(MethodView):

    def post(self):
        data = request.get_json()
        username = data.get('username', None)
        password = data.get('password', None)
        criterion = [username, password, len(data) == 2]

        if not all(criterion):
            raise JWTError('Bad Request', 'Missing required credentials', status_code=400)

        user = _jwt.authentication_callback(username=username, password=password)

        if user:
            payload_handler = current_app.config['JWT_PAYLOAD_HANDLER']
            payload = payload_handler(user)
            encode_handler = current_app.config['JWT_ENCODE_HANDLER']
            return jsonify({'token': encode_handler(payload)})
        else:
            raise JWTError('Bad Request', 'Invalid credentials')


class JWT(object):

    def __init__(self, app=None):
        if app is not None:
            self.app = app
            self.init_app(app)
        else:
            self.app = None

    def init_app(self, app):
        for k, v in CONFIG_DEFAULTS.items():
            app.config.setdefault(k, v)
        app.config.setdefault('JWT_SECRET_KEY', app.config['SECRET_KEY'])

        url_rule = app.config.get('JWT_AUTH_URL_RULE', None)
        endpoint = app.config.get('JWT_AUTH_ENDPOINT', None)

        if url_rule and endpoint:
            auth_view = JWTAuthView.as_view(app.config['JWT_AUTH_ENDPOINT'])
            app.add_url_rule(url_rule, methods=['POST'], view_func=auth_view)

        app.errorhandler(JWTError)(self._on_jwt_error)

        if not hasattr(app, 'extensions'):  # pragma: no cover
            app.extensions = {}
        app.extensions['jwt'] = self

    def _on_jwt_error(self, e):
        return getattr(self, 'error_callback', self._error_callback)(e)

    def _error_callback(self, e):
        return jsonify(OrderedDict([
            ('status_code', e.status_code),
            ('error', e.error),
            ('description', e.description),
        ])), e.status_code, e.headers

    def authentication_handler(self, callback):
        """Specifies the authentication handler function. This function receives two
        positional arguments. The first being the username the second being the password.
        It should return an object representing the authenticated user. Example::

            @jwt.authentication_handler
            def authenticate(username, password):
                if username == 'joe' and password == 'pass':
                    return User(id=1, username='joe')

        :param callback: the authentication handler function
        """
        self.authentication_callback = callback
        return callback

    def user_handler(self, callback):
        """Specifies the user handler function. This function receives the token payload as
        it's only positional argument. It should return an object representing the current
        user. Example::

            @jwt.user_handler
            def load_user(payload):
                if payload['user_id'] == 1:
                    return User(id=1, username='joe')

        :param callback: the user handler function
        """
        self.user_callback = callback
        return callback

    def error_handler(self, callback):
        """Specifies the error handler function. This function receives a JWTError instance as
        it's only positional argument. It can optionally return a response. Example::

            @jwt.error_handler
            def error_handler(e):
                return "Something bad happened", 400

        :param callback: the error handler function
        """
        self.error_callback = callback
        return callback
