# -*- coding: utf-8 -*-
"""
    tests.test_jwt
    ~~~~~~~~~~~~~~

    Flask-JWT tests
"""
import time

from itsdangerous import TimedJSONWebSignatureSerializer

from flask import Flask, json, jsonify

import flask_jwt


def post_json(client, url, data):
    resp = client.post(
        url,
        headers={'content-type': 'application/json'},
        data=json.dumps(data)
    )
    return resp, json.loads(resp.data)


def assert_error_response(r, code, msg, desc):
    jdata = json.loads(r.data)
    assert r.status_code == code
    assert jdata['status_code'] == code
    assert jdata['error'] == msg
    assert jdata['description'] == desc


def test_initialize():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'super-secret'
    jwt = flask_jwt.JWT(app)
    assert isinstance(jwt, flask_jwt.JWT)
    assert len(app.url_map._rules) == 2


def test_adds_auth_endpoint():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['JWT_AUTH_URL_RULE'] = '/auth'
    app.config['JWT_AUTH_ENDPOINT'] = 'jwt_auth'
    flask_jwt.JWT(app)
    rules = [str(r) for r in app.url_map._rules]
    assert '/auth' in rules


def test_auth_endpoint_with_valid_request(client, user):
    resp, jdata = post_json(
        client,
        '/auth',
        {'username': user.username, 'password': user.password}
    )
    assert resp.status_code == 200
    assert 'token' in jdata


def test_auth_endpoint_with_invalid_request(client, user):
    # Invalid request (no password)
    resp, jdata = post_json(client, '/auth', {'username': user.username})
    assert resp.status_code == 400
    assert 'error' in jdata
    assert jdata['error'] == 'Bad Request'
    assert 'description' in jdata
    assert jdata['description'] == 'Missing required credentials'
    assert 'status_code' in jdata
    assert jdata['status_code'] == 400


def test_auth_endpoint_with_invalid_credentials(client):
    resp, jdata = post_json(
        client,
        '/auth',
        {'username': 'bogus', 'password': 'bogus'}
    )
    assert resp.status_code == 400
    assert 'error' in jdata
    assert jdata['error'] == 'Bad Request'
    assert 'description' in jdata
    assert jdata['description'] == 'Invalid credentials'
    assert 'status_code' in jdata
    assert jdata['status_code'] == 400


def test_jwt_required_decorator_with_valid_token(app, client, user):
    _, jdata = post_json(
        client,
        '/auth',
        {'username': user.username, 'password': user.password}
    )
    token = jdata['token']
    resp = client.get(
        '/protected',
        headers={'authorization': 'Bearer ' + token})
    assert resp.status_code == 200
    assert resp.data == b'success'


def test_jwt_required_decorator_with_valid_request_current_user(app, client, user):
    with client as c:
        _, jdata = post_json(
            client,
            '/auth',
            {'username': user.username, 'password': user.password}
        )
        token = jdata['token']

        c.get(
            '/protected',
            headers={'authorization': 'Bearer ' + token})
        assert flask_jwt.current_user


def test_jwt_required_decorator_with_invalid_request_current_user(app, client):
    with client as c:
        c.get(
            '/protected',
            headers={'authorization': 'Bearer bogus'})
        assert not flask_jwt.current_user


def test_jwt_required_decorator_with_invalid_authorization_headers(app, client):
    # Missing authorization header
    r = client.get('/protected')
    assert_error_response(r, 401, 'Authorization Required', 'Authorization header was missing')
    assert r.headers['WWW-Authenticate'] == 'JWT realm="Login Required"'

    # Not a bearer token
    r = client.get('/protected', headers={'authorization': 'Bogus xxx'})
    assert_error_response(r, 400, 'Invalid JWT header', 'Unsupported authorization type')

    # Missing token
    r = client.get('/protected', headers={'authorization': 'Bearer'})
    assert_error_response(r, 400, 'Invalid JWT header', 'Token missing')

    # Token with spaces
    r = client.get('/protected', headers={'authorization': 'Bearer xxx xxx'})
    assert_error_response(r, 400, 'Invalid JWT header', 'Token contains spaces')


def test_jwt_required_decorator_with_invalid_jwt_tokens(client, user):
    _, jdata = post_json(
        client,
        '/auth',
        {'username': user.username, 'password': user.password}
    )
    token = jdata['token']

    # Undecipherable
    r = client.get('/protected', headers={'authorization': 'Bearer %sX' % token})
    assert_error_response(r, 400, 'Invalid JWT', 'Token is undecipherable')

    # Expired
    time.sleep(1.5)
    r = client.get('/protected', headers={'authorization': 'Bearer ' + token})
    assert_error_response(r, 400, 'Invalid JWT', 'Token is expired')


def test_jwt_required_decorator_with_missing_user(client, jwt, user):
    _, jdata = post_json(
        client,
        '/auth',
        {'username': user.username, 'password': user.password}
    )
    token = jdata['token']

    @jwt.user_handler
    def load_user(payload):
        return None

    r = client.get('/protected', headers={'authorization': 'Bearer %s' % token})
    assert_error_response(r, 400, 'Invalid JWT', 'User does not exist')


def test_custom_error_handler(client, jwt):
    @jwt.error_handler
    def error_handler(e):
        return "custom"

    r = client.get('/protected')
    assert r.data == b'custom'


def test_custom_response_handler(client, jwt, user):

    @jwt.response_handler
    def resp_handler(payload):
        return jsonify({'mytoken': payload})

    _, jdata = post_json(
        client,
        '/auth',
        {'username': user.username, 'password': user.password}
    )
    assert 'mytoken' in jdata


def test_default_encode_handler(client, user, app):
    resp, jdata = post_json(
        client,
        '/auth',
        {'username': user.username, 'password': user.password}
    )

    serializer = TimedJSONWebSignatureSerializer(
        secret_key=app.config['JWT_SECRET_KEY']
    )
    decoded = serializer.loads(jdata['token'])
    assert decoded['user_id'] == user.id


def test_custom_encode_handler(client, jwt, user, app):
    serializer = TimedJSONWebSignatureSerializer(
        app.config['JWT_SECRET_KEY'],
        algorithm_name=app.config['JWT_ALGORITHM']
    )

    @jwt.encode_handler
    def encode_data(payload):
        return serializer.dumps({'foo': 42}).decode('utf-8')
    _, jdata = post_json(
        client,
        '/auth',
        {'username': user.username, 'password': user.password}
    )
    decoded = serializer.loads(jdata['token'])
    assert decoded == {'foo': 42}


def test_custom_decode_handler(client, user, jwt):

    @jwt.decode_handler
    def decode_data(data):
        return {'user_id': user.id}

    with client as c:
        _, jdata = post_json(
            client,
            '/auth',
            {'username': user.username, 'password': user.password}
        )
        token = jdata['token']

        c.get(
            '/protected',
            headers={'authorization': 'Bearer ' + token})
        assert flask_jwt.current_user == user


def test_custom_payload_handler(client, jwt, user):
    @jwt.user_handler
    def load_user(payload):
        if payload['id'] == user.id:
            return user

    @jwt.payload_handler
    def make_payload(u):
        return {
            'id': u.id
        }

    with client as c:
        _, jdata = post_json(
            client,
            '/auth',
            {'username': user.username, 'password': user.password}
        )
        token = jdata['token']

        c.get(
            '/protected',
            headers={'authorization': 'Bearer ' + token})
        assert flask_jwt.current_user == user
