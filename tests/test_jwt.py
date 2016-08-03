# -*- coding: utf-8 -*-
"""
    tests.test_jwt
    ~~~~~~~~~~~~~~

    Flask-JWT tests
"""
import time

from datetime import datetime, timedelta

import jwt as _jwt
import pytest

from flask import Flask, json, jsonify

import flask_jwt


def post_json(client, url, data):
    data = json.dumps(data)
    resp = client.post(url, headers={'Content-Type': 'application/json'}, data=data)
    return resp, json.loads(resp.data)


def assert_error_response(r, code, msg, desc):
    assert r.status_code == code
    jdata = json.loads(r.data)
    assert jdata['status_code'] == code
    assert jdata['error'] == msg
    assert jdata['description'] == desc


def test_initialize():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'super-secret'
    jwt = flask_jwt.JWT(app, lambda: None, lambda: None)
    assert isinstance(jwt, flask_jwt.JWT)
    assert len(app.url_map._rules) == 2


def test_adds_auth_endpoint():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['JWT_AUTH_URL_RULE'] = '/auth'
    app.config['JWT_AUTH_ENDPOINT'] = 'jwt_auth'
    flask_jwt.JWT(app, lambda: None, lambda: None)
    rules = [str(r) for r in app.url_map._rules]
    endpoints = [r.endpoint for r in app.url_map.iter_rules()]
    assert '/auth' in rules
    assert 'jwt_auth' in endpoints


def test_auth_endpoint_with_valid_request(client, user):
    resp, jdata = post_json(
        client, '/auth', {'username': user.username, 'password': user.password})
    assert resp.status_code == 200
    assert 'access_token' in jdata


def test_custom_auth_endpoint_with_valid_request(app, client, user):
    app.config['JWT_AUTH_USERNAME_KEY'] = 'email'
    app.config['JWT_AUTH_PASSWORD_KEY'] = 'pass'
    resp, jdata = post_json(
        client,
        '/auth',
        {'email': user.username, 'pass': user.password}
    )
    assert resp.status_code == 200
    assert 'access_token' in jdata


def test_auth_endpoint_with_invalid_request(client, user):
    # Invalid request (no password)
    resp, jdata = post_json(client, '/auth', {'username': user.username})
    assert resp.status_code == 401
    assert 'error' in jdata
    assert jdata['error'] == 'Bad Request'
    assert 'description' in jdata
    assert jdata['description'] == 'Invalid credentials'
    assert 'status_code' in jdata
    assert jdata['status_code'] == 401


def test_auth_endpoint_with_invalid_credentials(client):
    resp, jdata = post_json(
        client, '/auth', {'username': 'bogus', 'password': 'bogus'})

    assert resp.status_code == 401
    assert 'error' in jdata
    assert jdata['error'] == 'Bad Request'
    assert 'description' in jdata
    assert jdata['description'] == 'Invalid credentials'
    assert 'status_code' in jdata
    assert jdata['status_code'] == 401


def test_auth_endpoint_with_invalid_body_post(client):
    resp = client.post('/auth', headers={})
    jdata = json.loads(resp.data)

    assert resp.status_code == 401
    assert 'error' in jdata
    assert jdata['error'] == 'Bad Request'
    assert 'description' in jdata
    assert jdata['description'] == 'Credentials must supplied in JSON'
    assert 'status_code' in jdata
    assert jdata['status_code'] == 401


def test_jwt_required_decorator_with_valid_token(app, client, user):
    resp, jdata = post_json(
        client, '/auth', {'username': user.username, 'password': user.password})

    token = jdata['access_token']
    resp = client.get('/protected', headers={'Authorization': 'JWT ' + token})

    assert resp.status_code == 200
    assert resp.data == b'success'


def test_jwt_required_decorator_with_valid_request_current_identity(app, client, user):
    with client as c:
        resp, jdata = post_json(
            client, '/auth', {'username': user.username, 'password': user.password})
        token = jdata['access_token']

        c.get(
            '/protected',
            headers={'authorization': 'JWT ' + token})
        assert flask_jwt.current_identity


def test_jwt_required_decorator_with_invalid_request_current_identity(app, client):
    with client as c:
        c.get('/protected', headers={'authorization': 'JWT bogus'})
        assert flask_jwt.current_identity._get_current_object() is None


def test_jwt_required_decorator_with_invalid_authorization_headers(app, client):
    # Missing authorization header
    r = client.get('/protected')

    assert_error_response(
        r, 401, 'Authorization Required', 'Request does not contain an access token')

    assert r.headers['WWW-Authenticate'] == 'JWT realm="Login Required"'

    # Not a JWT auth header prefix
    r = client.get('/protected', headers={'authorization': 'Bogus xxx'})

    assert_error_response(
        r, 401, 'Invalid JWT header', 'Unsupported authorization type')

    # Missing token
    r = client.get('/protected', headers={'authorization': 'JWT'})

    assert_error_response(
        r, 401, 'Invalid JWT header', 'Token missing')

    # Token with spaces
    r = client.get('/protected', headers={'authorization': 'JWT xxx xxx'})

    assert_error_response(
        r, 401, 'Invalid JWT header', 'Token contains spaces')


def test_jwt_required_decorator_with_invalid_jwt_tokens(client, user, app):
    app.config['JWT_LEEWAY'] = timedelta(seconds=0)
    app.config['JWT_EXPIRATION_DELTA'] = timedelta(milliseconds=200)

    resp, jdata = post_json(
        client, '/auth', {'username': user.username, 'password': user.password})
    token = jdata['access_token']

    # Undecipherable
    r = client.get('/protected', headers={'authorization': 'JWT %sX' % token})
    assert_error_response(r, 401, 'Invalid token', 'Signature verification failed')

    # Expired
    time.sleep(1.5)
    r = client.get('/protected', headers={'authorization': 'JWT ' + token})
    assert_error_response(r, 401, 'Invalid token', 'Signature has expired')


def test_jwt_required_decorator_with_missing_user(client, jwt, user):
    resp, jdata = post_json(
        client, '/auth', {'username': user.username, 'password': user.password})
    token = jdata['access_token']

    @jwt.identity_handler
    def load_user(payload):
        return None

    r = client.get('/protected', headers={'authorization': 'JWT %s' % token})
    assert_error_response(r, 401, 'Invalid JWT', 'User does not exist')


def test_custom_error_handler(client, jwt):
    @jwt.error_handler
    def error_handler(e):
        return "custom"

    r = client.get('/protected')
    assert r.data == b'custom'


def test_custom_response_handler(client, jwt, user):
    @jwt.auth_response_handler
    def resp_handler(access_token, identity):
        return jsonify({'mytoken': access_token.decode('utf-8')})

    resp, jdata = post_json(
        client, '/auth', {'username': user.username, 'password': user.password})

    assert 'mytoken' in jdata


def test_custom_encode_handler(client, jwt, user, app):
    secret = app.config['JWT_SECRET_KEY']
    alg = 'HS256'

    @jwt.encode_handler
    def encode_data(identity):
        return _jwt.encode({'hello': 'world'}, secret, algorithm=alg)

    resp, jdata = post_json(
        client, '/auth', {'username': user.username, 'password': user.password})

    decoded = _jwt.decode(jdata['access_token'], secret, algorithms=[alg])

    assert decoded == {'hello': 'world'}


def test_custom_decode_handler(client, user, jwt):
    # The following function should receive the decode return value
    @jwt.identity_handler
    def load_user(payload):
        assert payload == {'user_id': user.id}

    @jwt.decode_handler
    def decode_data(token):
        return {'user_id': user.id}

    with client as c:
        resp, jdata = post_json(
            client, '/auth', {'username': user.username, 'password': user.password})

        token = jdata['access_token']

        c.get('/protected', headers={'authorization': 'JWT ' + token})


def test_custom_payload_handler(client, jwt, user):
    @jwt.identity_handler
    def load_user(payload):
        if payload['id'] == user.id:
            return user

    @jwt.payload_handler
    def make_payload(u):
        iat = datetime.utcnow()
        exp = iat + timedelta(seconds=60)
        nbf = iat + timedelta(seconds=0)
        return {'iat': iat, 'exp': exp, 'nbf': nbf, 'id': u.id}

    with client as c:
        resp, jdata = post_json(
            client, '/auth', {'username': user.username, 'password': user.password})

        token = jdata['access_token']

        c.get('/protected', headers={'authorization': 'JWT ' + token})
        assert flask_jwt.current_identity == user


def test_custom_auth_header(app, client, user):
    app.config['JWT_AUTH_HEADER_PREFIX'] = 'Bearer'

    with client as c:
        resp, jdata = post_json(
            client, '/auth', {'username': user.username, 'password': user.password})

        token = jdata['access_token']

        # Custom Bearer auth header prefix
        resp = c.get('/protected', headers={'authorization': 'Bearer ' + token})
        assert resp.status_code == 200
        assert resp.data == b'success'

        # Not custom Bearer auth header prefix
        resp = c.get('/protected', headers={'authorization': 'JWT ' + token})
        assert_error_response(resp, 401, 'Invalid JWT header', 'Unsupported authorization type')


def test_custom_auth_handler():
    def custom_auth_request_handler():
        return jsonify({'hello': 'world'})

    jwt = flask_jwt.JWT()
    pytest.deprecated_call(jwt.auth_request_handler, custom_auth_request_handler)

    app = Flask(__name__)
    jwt.init_app(app)

    with app.test_client() as c:
        resp, jdata = post_json(c, '/auth', {})
        assert jdata == {'hello': 'world'}


def test_audience(client, jwt, user, app):
    aud = 'http://audience/'
    app.config['JWT_AUDIENCE'] = aud

    @jwt.identity_handler
    def load_user(payload):
        if payload['id'] == user.id:
            return user

    @jwt.payload_handler
    def make_payload(u):
        iat = datetime.utcnow()
        exp = iat + timedelta(seconds=60)
        nbf = iat + timedelta(seconds=0)
        return {'iat': iat, 'exp': exp, 'nbf': nbf, 'id': u.id, 'aud': aud}

    with client as c:
        resp, jdata = post_json(
            client, '/auth', {'username': user.username, 'password': user.password})

        token = jdata['access_token']

        resp = c.get('/protected', headers={'authorization': 'JWT ' + token})
        assert resp.status_code == 200
        assert 'access_token' in jdata


def test_default_encode_handler_user_object(app, client, jwt, user):
    with app.app_context():
        token = jwt.jwt_encode_callback(user)

        with client as c:
            c.get('/protected', headers={'authorization': 'JWT ' + token.decode('utf-8')})
            assert flask_jwt.current_identity == user


def test_default_encode_handler_dictuser(dictuserapp, jwt, dictuser):
    with dictuserapp.app_context():
        token = jwt.jwt_encode_callback(dictuser)

        with dictuserapp.test_client() as c:
            c.get('/protected', headers={'authorization': 'JWT ' + token.decode('utf-8')})
            assert flask_jwt.current_identity == dictuser
