
from unittest import TestCase

import flask_jwt
from flask import Flask, json

from nose.tools import *


class User(object):
    def __init__(self, **kwargs):
        for k, v in kwargs.iteritems():
            setattr(self, k, v)


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['JWT_AUTH_URL_RULE'] = '/auth'
    app.config['JWT_AUTH_ENDPOINT'] = 'jwt_auth'
    jwt = flask_jwt.JWT(app)

    @jwt.authentication_handler
    def authenticate(username, password):
        if username == 'joe' and password == 'pass':
            return User(id=1, username='joe')
        None

    client = app.test_client()
    return app, client



class JWTTestCase(TestCase):

    def test_initialize(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'super-secret'
        jwt = flask_jwt.JWT(app)
        assert_true(isinstance(jwt, flask_jwt.JWT))
        assert_equals(1, len(app.url_map._rules))

    def test_adds_auth_endpoint(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'super-secret'
        app.config['JWT_AUTH_URL_RULE'] = '/auth'
        app.config['JWT_AUTH_ENDPOINT'] = 'jwt_auth'
        flask_jwt.JWT(app)
        rules = [str(r) for r in app.url_map._rules]
        assert_true('/auth' in rules)

    def test_auth_endpoint_with_valid_request(self):
        app, client = create_app()
        r = client.post('/auth',
            headers={'content-type': 'application/json'},
            data=json.dumps({
                'username': 'joe',
                'password': 'pass'
            }))
        assert_equals(200, r.status_code)
        jdata = json.loads(r.data)
        assert_true('token' in jdata)

    def test_auth_endpoint_with_invalid_request(self):
        app, client = create_app()
        # Invalid request
        r = client.post('/auth',
            headers={'content-type': 'application/json'},
            data=json.dumps({
                'username': 'joe'
            }))
        assert_equals(400, r.status_code)
        jdata = json.loads(r.data)
        assert_true('error' in jdata)
        assert_equals(jdata['error'], 'Bad Request')
        assert_true('description' in jdata)
        assert_equals(jdata['description'], 'Missing required credentials')
        assert_true('status_code' in jdata)
        assert_equals(jdata['status_code'], 400)

    def test_auth_endpoint_with_invalid_credentials(self):
        app, client = create_app()
        # Invalid credentials
        r = client.post('/auth',
            headers={'content-type': 'application/json'},
            data=json.dumps({
                'username': 'bogus',
                'password': 'bogus'
            }))
        assert_equals(400, r.status_code)
        jdata = json.loads(r.data)
        assert_true('error' in jdata)
        assert_equals(jdata['error'], 'Bad Request')
        assert_true('description' in jdata)
        assert_equals(jdata['description'], 'Invalid credentials')
        assert_true('status_code' in jdata)
        assert_equals(jdata['status_code'], 400)

    def test_jwt_required_decorator_with_valid_token(self):
        app, client = create_app()

        @app.route('/protected')
        @flask_jwt.jwt_required()
        def protected():
            return 'success'

        r = client.post('/auth',
            headers={'content-type': 'application/json'},
            data=json.dumps({
                'username': 'joe',
                'password': 'pass'
            }))

        jdata = json.loads(r.data)
        token = jdata['token']

        r = client.get('/protected',
            headers={'authorization': 'Bearer ' + token})
        assert_equals(200, r.status_code)
        assert_equals('success', r.data)


    def test_jwt_required_decorator_with_missing_token(self):
        app, client = create_app()

        @app.route('/protected')
        @flask_jwt.jwt_required()
        def protected():
            return 'success'

        r = client.get('/protected')
        jdata = json.loads(r.data)
        assert_equals(401, r.status_code)
        assert_equals(401, jdata['status_code'])
        assert_equals('Authorization Required', jdata['error'])
        assert_equals('Authorization header was missing', jdata['description'])

