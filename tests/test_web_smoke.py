import flask
import importlib

from helper import env, config, user


config_env = config('web_secret.cfg')
config_env_nosecret = config('web_nosecret.cfg')


def _import_app():
    import committee
    importlib.reload(committee)  # force reload (config could change)
    if hasattr(committee, 'app'):
        return committee.app
    elif hasattr(committee, 'create_app'):
        return committee.create_app(None)
    else:
        raise RuntimeError(
            "Can't find a Flask app. "
            "Either instantiate `committee.app` variable "
            "or implement `committee.create_app(dummy)` function. "
            "See https://flask.palletsprojects.com/en/1.1.x/patterns/appfactories/"
            "for additional information."
        )


def _test_app():
    app = _import_app()
    app.config['TESTING'] = True
    return app.test_client()


def test_app_imports():
    with env(COMMITTEE_CONFIG=config_env):
        app = _import_app()
        assert isinstance(app, flask.Flask)


def test_app_get_has_username():
    with env(COMMITTEE_CONFIG=config_env):
        app = _test_app()
        assert user in app.get('/').get_data(as_text=True)


def test_app_get_has_rules():
    with env(COMMITTEE_CONFIG=config_env):
        app = _test_app()
        text = app.get('/').get_data(as_text=True)
        assert 'no-shits' in text
        assert 'There is something shitty.' in text
        assert 'persist-readme' in text
        assert 'README is important, do not delete it.' in text
        assert 'relatively-forbidden' in text
        assert 'There are some relatively forbidden words in the message.' in text
        assert 'many-changes' in text
        assert 'Too many changes in the file.' in text


# If you change this, the Signature bellow must be updated!
PING = {
    'zen': 'Keep it logically awesome.',
    'hook_id': 123456,
    'hook': {
        'type': 'Repository',
        'id': 55866886,
        'name': 'web',
        'active': True,
        'events': [
            'push',
        ],
        'config': {
            'content_type': 'json',
            'insecure_ssl': '0',
            'secret': '********',
        },
    },
    'repository': {
        'id': 123456,
        'name': 'committee',
        'full_name': 'cvut/committee',
        'private': False,
    },
    'sender': {
        'login': 'user',
    },
}


def test_ping_pong():
    with env(COMMITTEE_CONFIG=config_env):
        app = _test_app()
        rv = app.post('/', json=PING, headers={
            'X-Hub-Signature': 'sha1=578851772a72bb7f96001fb28d7217642e344d3b',
            'X-GitHub-Event': 'ping'})
        assert rv.status_code == 200


def test_dangerous_ping_pong():
    with env(COMMITTEE_CONFIG=config_env_nosecret):
        app = _test_app()
        rv = app.post('/', json=PING, headers={'X-GitHub-Event': 'ping'})
        assert rv.status_code == 200


def test_bad_secret():
    with env(COMMITTEE_CONFIG=config_env):
        app = _test_app()
        rv = app.post('/', json=PING, headers={
            'X-Hub-Signature': 'sha1=1cacacc4207bdd4a51a7528bd9a5b9d6546b0c22',
            'X-GitHub-Event': 'ping'})
        assert rv.status_code >= 400
