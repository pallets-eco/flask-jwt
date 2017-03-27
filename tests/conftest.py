# -*- coding: utf-8 -*-
"""
    tests.conftest
    ~~~~~~~~~~~~~~

    Test fixtures and what not
"""

import logging

import pytest

from flask import Flask
from datetime import datetime, timedelta

import flask_jwt

logging.basicConfig(level=logging.DEBUG)


class User(object):
    def __init__(self, id, username, password, role=None):
        self.id = id
        self.username = username
        self.password = password
        if role:
            self.role = role

    def __str__(self):
        return "User(id='%s')" % self.id


@pytest.fixture(scope='function')
def jwt():
    return flask_jwt.JWT()


@pytest.fixture(scope='function')
def user():
    return User(id=1, username='joe', password='pass')


@pytest.fixture(scope='function')
def user_with_role():
    return User(id=2, username='jane', password='pass', role='user')


@pytest.fixture(scope='function')
def user_with_roles():
    return User(id=3, username='alice', password='pass', role=['user', 'foo', 'bar'])


@pytest.fixture(scope='function')
def app(jwt, user):
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'super-secret'

    @jwt.authentication_handler
    def authenticate(username, password):
        if username == user.username and password == user.password:
            return user
        return None

    @jwt.identity_handler
    def load_user(payload):
        if payload['identity'] == user.id:
            return user

    jwt.init_app(app)

    @app.route('/protected')
    @flask_jwt.jwt_required()
    def protected():
        return 'success'

    return app


@pytest.fixture(scope='function')
def app_with_role(jwt, user, user_with_role, user_with_roles):
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'super-secret'
    users = [user, user_with_role, user_with_roles]

    @jwt.authentication_handler
    def authenticate(username, password):
        for u in users:
            if username == u.username and password == u.password:
                return u
        return None

    @jwt.identity_handler
    def load_user(payload):
        for u in users:
            if payload['identity'] == u.id:
                return u

    @jwt.payload_handler
    def make_payload(identity):
        iat = datetime.utcnow()
        exp = iat + timedelta(seconds=300)
        nbf = iat
        id = getattr(identity, 'id')
        try:
            role = getattr(identity, 'role')
            return {'exp': exp, 'iat': iat, 'nbf': nbf, 'identity': id, 'role': role}
        except AttributeError:
            return {'exp': exp, 'iat': iat, 'nbf': nbf, 'identity': id}

    jwt.init_app(app)

    @app.route('/protected')
    @flask_jwt.jwt_required()
    def protected():
        return 'success'

    @app.route('/role/protected/admin')
    @flask_jwt.jwt_required(roles='admin')
    def admin_protected():
        return 'success'

    @app.route('/role/protected/multi')
    @flask_jwt.jwt_required(roles=['admin', 'user'])
    def admin_user_protected():
        return 'success'

    @app.route('/role/protected/user')
    @flask_jwt.jwt_required(roles='user')
    def user_protected():
        return 'success'

    return app


@pytest.fixture(scope='function')
def app_with_role_trust_jwt(jwt, user, user_with_role, user_with_roles):
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['JWT_ROLE'] = 'my_role'
    users = [user, user_with_role, user_with_roles]

    @jwt.authentication_handler
    def authenticate(username, password):
        for u in users:
            if username == u.username and password == u.password:
                return u
        return None

    @jwt.identity_handler
    def load_user(payload):
        return payload

    @jwt.payload_handler
    def make_payload(identity):
        iat = datetime.utcnow()
        exp = iat + timedelta(seconds=300)
        nbf = iat
        id = getattr(identity, 'id')
        try:
            role = getattr(identity, 'role')
            return {'exp': exp, 'iat': iat, 'nbf': nbf, 'identity': id, 'my_role': role}
        except AttributeError:
            return {'exp': exp, 'iat': iat, 'nbf': nbf, 'identity': id}

    jwt.init_app(app)

    @app.route('/protected')
    @flask_jwt.jwt_required()
    def protected():
        return 'success'

    @app.route('/role/protected/user')
    @flask_jwt.jwt_required(roles='user')
    def user_protected():
        return 'success'

    @app.route('/role/protected/multi')
    @flask_jwt.jwt_required(roles=['admin', 'user'])
    def admin_user_protected():
        return 'success'

    @app.route('/role/protected/admin')
    @flask_jwt.jwt_required(roles='admin')
    def admin_protected():
        return 'success'

    return app


@pytest.fixture(scope='function')
def client(app):
    return app.test_client()


@pytest.fixture(scope='function')
def dictuserapp(jwt, dictuser):
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'super-secret'

    @jwt.authentication_handler
    def authenticate(username, password):
        if username == dictuser['username'] and password == dictuser['password']:
            return dictuser
        return None

    @jwt.identity_handler
    def load_user(payload):
        if payload['identity'] == dictuser['id']:
            return dictuser

    jwt.init_app(app)

    @app.route('/protected')
    @flask_jwt.jwt_required()
    def protected():
        return 'success'

    return app


@pytest.fixture(scope='function')
def dictuser():
    return {'id': 1, 'username': 'joe', 'password': 'pass'}
