# -*- coding: utf-8 -*-
"""
    flask_jwt
    ~~~~~~~~~

    Flask-JWT module
"""

from collections import OrderedDict
from datetime import timedelta
from functools import wraps

from itsdangerous import (
    TimedJSONWebSignatureSerializer,
    SignatureExpired,
    BadSignature
)

from flask import current_app, request, jsonify, _request_ctx_stack
from flask.views import MethodView
from werkzeug.local import LocalProxy

__version__ = '0.2.0'

current_user = LocalProxy(lambda: getattr(_request_ctx_stack.top, 'current_user', None))

_jwt = LocalProxy(lambda: current_app.extensions['jwt'])


def _get_serializer():
    expires_in = current_app.config['JWT_EXPIRATION_DELTA']
    if isinstance(expires_in, timedelta):
        expires_in = int(expires_in.total_seconds())
    expires_in_total = expires_in + current_app.config['JWT_LEEWAY']
    return TimedJSONWebSignatureSerializer(
        secret_key=current_app.config['JWT_SECRET_KEY'],
        expires_in=expires_in_total,
        algorithm_name=current_app.config['JWT_ALGORITHM']
    )


def _default_payload_handler(user):
    return {
        'user_id': user.id,
    }


def _default_encode_handler(payload):
    """Return the encoded payload."""
    return _get_serializer().dumps(payload).decode('utf-8')


def _default_decode_handler(token):
    """Return the decoded token."""
    try:
        result = _get_serializer().loads(token)
    except SignatureExpired:
        if current_app.config['JWT_VERIFY_EXPIRATION']:
            raise
    return result


def _default_response_handler(payload):
    """Return a Flask response, given an encoded payload."""
    return jsonify({'token': payload})

CONFIG_DEFAULTS = {
    'JWT_DEFAULT_REALM': 'Login Required',
    'JWT_AUTH_URL_RULE': '/auth',
    'JWT_AUTH_ENDPOINT': 'jwt',
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
    """Does the actual work of verifying the JWT data in the current request.
    This is done automatically for you by `jwt_required()` but you could call it manually.
    Doing so would be useful in the context of optional JWT access in your APIs.

    :param realm: an optional realm
    """
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
        handler = _jwt.decode_callback
        payload = handler(parts[1])
    except SignatureExpired:
        raise JWTError('Invalid JWT', 'Token is expired')
    except BadSignature:
        raise JWTError('Invalid JWT', 'Token is undecipherable')

    _request_ctx_stack.top.current_user = user = _jwt.user_callback(payload)

    if user is None:
        raise JWTError('Invalid JWT', 'User does not exist')


class JWTAuthView(MethodView):

    def post(self):
        data = request.get_json(force=True)
        username = data.get('username', None)
        password = data.get('password', None)
        criterion = [username, password, len(data) == 2]

        if not all(criterion):
            raise JWTError('Bad Request', 'Missing required credentials', status_code=400)

        user = _jwt.authentication_callback(username=username, password=password)

        if user:
            payload = _jwt.payload_callback(user)
            token = _jwt.encode_callback(payload)
            return _jwt.response_callback(token)
        else:
            raise JWTError('Bad Request', 'Invalid credentials')


class JWT(object):

    def __init__(self, app=None):
        if app is not None:
            self.app = app
            self.init_app(app)
        else:
            self.app = None

        # Set default handlers
        self.response_callback = _default_response_handler
        self.encode_callback = _default_encode_handler
        self.decode_callback = _default_decode_handler
        self.payload_callback = _default_payload_handler

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
        its only positional argument. It should return an object representing the current
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
        its only positional argument. It can optionally return a response. Example::

            @jwt.error_handler
            def error_handler(e):
                return "Something bad happened", 400

        :param callback: the error handler function
        """
        self.error_callback = callback
        return callback

    def response_handler(self, callback):
        """Specifies the response handler function. This function receives a
        JWT-encoded payload and returns a Flask response.

        :param callable callback: the response handler function
        """
        self.response_callback = callback
        return callback

    def encode_handler(self, callback):
        """Specifies the encoding handler function. This function receives a
        payload and signs it.

        :param callable callback: the encoding handler function
        """
        self.encode_callback = callback
        return callback

    def decode_handler(self, callback):
        """Specifies the decoding handler function. This function receives a
        signed payload and decodes it.

        :param callable callback: the decoding handler function
        """
        self.decode_callback = callback
        return callback

    def payload_handler(self, callback):
        """Specifies the payload handler function. This function receives a
        user object and returns a dictionary payload.

        Example::

            @jwt.payload_handler
            def make_payload(user):
                return {
                    'user_id': user.id,
                    'exp': datetime.utcnow() + current_app.config['JWT_EXPIRATION_DELTA']
                }

        :param callable callback: the payload handler function
        """
        self.payload_callback = callback
        return callback
