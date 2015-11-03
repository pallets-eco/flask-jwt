# -*- coding: utf-8 -*-
"""
    flask_jwt
    ~~~~~~~~~

    Flask-JWT module
"""

import logging
import warnings

from collections import OrderedDict
from datetime import datetime, timedelta
from functools import wraps

import jwt

from flask import current_app, request, jsonify, _request_ctx_stack
from werkzeug.local import LocalProxy

__version__ = '0.3.2'

logger = logging.getLogger(__name__)

current_identity = LocalProxy(lambda: getattr(_request_ctx_stack.top, 'current_identity', None))

_jwt = LocalProxy(lambda: current_app.extensions['jwt'])

CONFIG_DEFAULTS = {
    'JWT_DEFAULT_REALM': 'Login Required',
    'JWT_AUTH_URL_RULE': '/auth',
    'JWT_AUTH_ENDPOINT': 'jwt',
    'JWT_AUTH_USERNAME_KEY': 'username',
    'JWT_AUTH_PASSWORD_KEY': 'password',
    'JWT_ALGORITHM': 'HS256',
    'JWT_LEEWAY': timedelta(seconds=10),
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'JWT_EXPIRATION_DELTA': timedelta(seconds=300),
    'JWT_NOT_BEFORE_DELTA': timedelta(seconds=0),
    'JWT_VERIFY_CLAIMS': ['signature', 'exp', 'nbf', 'iat'],
    'JWT_REQUIRED_CLAIMS': ['exp', 'iat', 'nbf']
}


def _default_jwt_headers_handler(identity):
    return None


def _default_jwt_payload_handler(identity):
    iat = datetime.utcnow()
    exp = iat + current_app.config.get('JWT_EXPIRATION_DELTA')
    nbf = iat + current_app.config.get('JWT_NOT_BEFORE_DELTA')
    identity = getattr(identity, 'id') or identity['id']
    return {'exp': exp, 'iat': iat, 'nbf': nbf, 'identity': identity}


def _default_jwt_encode_handler(identity):
    secret = current_app.config['JWT_SECRET_KEY']
    algorithm = current_app.config['JWT_ALGORITHM']
    required_claims = current_app.config['JWT_REQUIRED_CLAIMS']

    payload = _jwt.jwt_payload_callback(identity)
    missing_claims = list(set(required_claims) - set(payload.keys()))

    if missing_claims:
        raise RuntimeError('Payload is missing required claims: %s' % ', '.join(missing_claims))

    headers = _jwt.jwt_headers_callback(identity)

    return jwt.encode(payload, secret, algorithm=algorithm, headers=headers)


def _default_jwt_decode_handler(token):
    secret = current_app.config['JWT_SECRET_KEY']
    algorithm = current_app.config['JWT_ALGORITHM']
    leeway = current_app.config['JWT_LEEWAY']

    verify_claims = current_app.config['JWT_VERIFY_CLAIMS']
    required_claims = current_app.config['JWT_REQUIRED_CLAIMS']

    options = {
        'verify_' + claim: True
        for claim in verify_claims
    }

    options.update({
        'require_' + claim: True
        for claim in required_claims
    })

    return jwt.decode(token, secret, options=options, algorithms=[algorithm], leeway=leeway)


def _default_request_handler():
    auth_header_value = request.headers.get('Authorization', None)
    auth_header_prefix = current_app.config['JWT_AUTH_HEADER_PREFIX']

    if not auth_header_value:
        return

    parts = auth_header_value.split()

    if parts[0].lower() != auth_header_prefix.lower():
        raise JWTError('Invalid JWT header', 'Unsupported authorization type')
    elif len(parts) == 1:
        raise JWTError('Invalid JWT header', 'Token missing')
    elif len(parts) > 2:
        raise JWTError('Invalid JWT header', 'Token contains spaces')

    return parts[1]


def _default_auth_request_handler():
    data = request.get_json()
    username = data.get(current_app.config.get('JWT_AUTH_USERNAME_KEY'), None)
    password = data.get(current_app.config.get('JWT_AUTH_PASSWORD_KEY'), None)
    criterion = [username, password, len(data) == 2]

    if not all(criterion):
        raise JWTError('Bad Request', 'Invalid credentials')

    identity = _jwt.authentication_callback(username, password)

    if identity:
        access_token = _jwt.jwt_encode_callback(identity)
        return _jwt.auth_response_callback(access_token, identity)
    else:
        raise JWTError('Bad Request', 'Invalid credentials')


def _default_auth_response_handler(access_token, identity):
    return jsonify({'access_token': access_token.decode('utf-8')})


def _default_jwt_error_handler(error):
    logger.error(error)
    return jsonify(OrderedDict([
        ('status_code', error.status_code),
        ('error', error.error),
        ('description', error.description),
    ])), error.status_code, error.headers


def _jwt_required(realm):
    """Does the actual work of verifying the JWT data in the current request.
    This is done automatically for you by `jwt_required()` but you could call it manually.
    Doing so would be useful in the context of optional JWT access in your APIs.

    :param realm: an optional realm
    """
    token = _jwt.request_callback()

    if token is None:
        raise JWTError('Authorization Required', 'Request does not contain an access token',
                       headers={'WWW-Authenticate': 'JWT realm="%s"' % realm})

    try:
        payload = _jwt.jwt_decode_callback(token)
    except jwt.InvalidTokenError as e:
        raise JWTError('Invalid token', str(e))

    _request_ctx_stack.top.current_identity = identity = _jwt.identity_callback(payload)

    if identity is None:
        raise JWTError('Invalid JWT', 'User does not exist')


def jwt_required(realm=None):
    """View decorator that requires a valid JWT token to be present in the request

    :param realm: an optional realm
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            _jwt_required(realm or current_app.config['JWT_DEFAULT_REALM'])
            return fn(*args, **kwargs)
        return decorator
    return wrapper


class JWTError(Exception):
    def __init__(self, error, description, status_code=401, headers=None):
        self.error = error
        self.description = description
        self.status_code = status_code
        self.headers = headers

    def __repr__(self):
        return 'JWTError: %s' % self.error

    def __str__(self):
        return '%s. %s' % (self.error, self.description)


def encode_token():
    return _jwt.encode_callback(_jwt.header_callback(), _jwt.payload_callback())


class JWT(object):

    def __init__(self, app=None, authentication_handler=None, identity_handler=None):
        self.authentication_callback = authentication_handler
        self.identity_callback = identity_handler

        self.auth_response_callback = _default_auth_response_handler
        self.auth_request_callback = _default_auth_request_handler
        self.jwt_encode_callback = _default_jwt_encode_handler
        self.jwt_decode_callback = _default_jwt_decode_handler
        self.jwt_headers_callback = _default_jwt_headers_handler
        self.jwt_payload_callback = _default_jwt_payload_handler
        self.jwt_error_callback = _default_jwt_error_handler
        self.request_callback = _default_request_handler

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        for k, v in CONFIG_DEFAULTS.items():
            app.config.setdefault(k, v)
        app.config.setdefault('JWT_SECRET_KEY', app.config['SECRET_KEY'])

        auth_url_rule = app.config.get('JWT_AUTH_URL_RULE', None)

        if auth_url_rule:
            if self.auth_request_callback == _default_auth_request_handler:
                assert self.authentication_callback is not None, (
                    'an authentication_handler function must be defined when using the built in '
                    'authentication resource')

            auth_url_options = app.config.get('JWT_AUTH_URL_OPTIONS', {'methods': ['POST']})
            auth_url_options.setdefault('view_func', self.auth_request_callback)
            app.add_url_rule(auth_url_rule, **auth_url_options)

        app.errorhandler(JWTError)(self._jwt_error_callback)

        if not hasattr(app, 'extensions'):  # pragma: no cover
            app.extensions = {}

        app.extensions['jwt'] = self

    def _jwt_error_callback(self, error):
        return self.jwt_error_callback(error)

    def authentication_handler(self, callback):
        """Specifies the identity handler function. This function receives two positional
        arguments. The first being the username the second being the password. It should return an
        object representing an authenticated identity. Example::

            @jwt.authentication_handler
            def authenticate(username, password):
                user = User.query.filter(User.username == username).scalar()
                if bcrypt.check_password_hash(user.password, password):
                    return user

        :param callback: the identity handler function
        """
        self.authentication_callback = callback
        return callback

    def identity_handler(self, callback):
        """Specifies the identity handler function. This function receives one positional argument
        being the JWT payload. For example::

            @jwt.identity_handler
            def identify(payload):
                return User.query.filter(User.id == payload['identity']).scalar()

        :param callback: the identity handler function
        """
        self.identity_callback = callback
        return callback

    def jwt_error_handler(self, callback):
        """Specifies the error handler function. Example::

            @jwt.error_handler
            def error_handler(e):
                return "Something bad happened", 400

        :param callback: the error handler function
        """
        self.jwt_error_callback = callback
        return callback

    def auth_response_handler(self, callback):
        """Specifies the authentication response handler function.

        :param callable callback: the auth response handler function
        """
        self.auth_response_callback = callback
        return callback

    def auth_request_handler(self, callback):
        """Specifies the authentication response handler function.

        :param callable callback: the auth request handler function

        .. deprecated
        """
        warnings.warn("This handler is deprecated. The recommended approach to have control over "
                      "the authentication resource is to disable the built-in  resource by "
                      "setting JWT_AUTH_URL_RULE=None and registering your own authentication "
                      "resource directly on your application.", DeprecationWarning, stacklevel=2)
        self.auth_request_callback = callback
        return callback

    def request_handler(self, callback):
        """Specifieds the request handler function. This function returns a JWT from the current
        request.

        :param callable callback: the request handler function
        """
        self.request_callback = callback
        return callback

    def jwt_encode_handler(self, callback):
        """Specifies the encoding handler function. This function receives a payload and signs it.

        :param callable callback: the encoding handler function
        """
        self.jwt_encode_callback = callback
        return callback

    def jwt_decode_handler(self, callback):
        """Specifies the decoding handler function. This function receives a
        signed payload and decodes it.

        :param callable callback: the decoding handler function
        """
        self.jwt_decode_callback = callback
        return callback

    def jwt_payload_handler(self, callback):
        """Specifies the JWT payload handler function. This function receives the return value from
        the ``identity_handler`` function

        Example::

            @jwt.payload_handler
            def make_payload(identity):
                return {'user_id': identity.id}

        :param callable callback: the payload handler function
        """
        self.jwt_payload_callback = callback
        return callback

    def jwt_headers_handler(self, callback):
        """Specifies the JWT header handler function. This function receives the return value from
        the ``identity_handler`` function.

        Example::

            @jwt.payload_handler
            def make_payload(identity):
                return {'user_id': identity.id}

        :param callable callback: the payload handler function
        """
        self.jwt_headers_callback = callback
        return callback
