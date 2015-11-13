# -*- coding: utf-8 -*-
"""
    tests.conftest
    ~~~~~~~~~~~~~~

    Test fixtures and what not
"""

import logging

import pytest

from flask import Flask

import flask_jwt

logging.basicConfig(level=logging.DEBUG)


class User(object):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def __str__(self):
        return "User(id='%s')" % self.id


@pytest.fixture(scope='function')
def jwt():
    return flask_jwt.JWT()


@pytest.fixture(scope='function')
def user():
    return User(id=1, username='joe', password='pass')


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
