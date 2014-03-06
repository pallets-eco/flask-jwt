# -*- coding: utf-8 -*-
"""
    tests.conftest
    ~~~~~~~~~~~~~~

    Test fixtures and what not
"""

from datetime import timedelta

import pytest

from flask import Flask

import flask_jwt


class User(object):
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


@pytest.fixture(scope='function')
def jwt():
    return flask_jwt.JWT()


@pytest.fixture(scope='function')
def app(jwt):
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['JWT_EXPIRATION_DELTA'] = timedelta(milliseconds=200)

    jwt.init_app(app)

    @jwt.authentication_handler
    def authenticate(username, password):
        if username == 'joe' and password == 'pass':
            return User(id=1, username='joe')
        None

    @jwt.user_handler
    def load_user(payload):
        if payload['user_id'] == 1:
            return User(id=1, username='joe')

    @app.route('/protected')
    @flask_jwt.jwt_required()
    def protected():
        return 'success'

    return app


@pytest.fixture(scope='function')
def client(app):
    return app.test_client()
