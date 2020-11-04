import configparser
import flask
import hashlib
import hmac
import os

from committee.config import ConfigLoader
from committee.logic import Committee, CommitteeResult, GitHubClient


ENVVAR_CONFIG = 'COMMITTEE_CONFIG'


def load_config_web(app):
    if ENVVAR_CONFIG not in os.environ:
        app.logger.critical(f'Config not supplied by envvar {ENVVAR_CONFIG}')
        exit(1)
    config_file = os.environ[ENVVAR_CONFIG]
    try:
        cfg = configparser.ConfigParser()
        cfg.optionxform = str
        cfg.read(config_file, encoding='utf-8')
        return ConfigLoader.load(cfg, config_file, web=True)
    except Exception:
        app.logger.critical('Failed to load the configuration!')
        exit(1)


class CommitteeLogPrinter:
    """Committee Printer for web-app logging"""

    def __init__(self, logger):
        self.logger = logger

    def failed_get_commits(self):
        pass

    def failed_get_commit(self, commit_item):
        sha = commit_item['sha']
        self.logger.error(f'Could not GET commit {sha}')

    def get_commit(self, commit):
        sha = commit['sha']
        short_message = commit['commit']['message'].splitlines()[0]
        self.logger.info(f'Received commit {sha}: {short_message}')

    def skipping_commit(self):
        pass

    def rule_done(self, rule, results):
        pass

    def rule_error(self, rule):
        pass

    def dry_update_status(self):
        pass

    def updated_status(self):
        self.logger.info(f'Updated commit status successfully')

    def failed_update_status(self):
        self.logger.error(f'Failed to update commit status')

    def finished(self, result):
        sha = result.commit['sha']
        res = 'SUCCESS' if result.status == CommitteeResult.SUCCESS else 'FAILURE'
        self.logger.info(f'Finished processing {sha}: {res} - {result.description}')




def webhook_verify_signature(payload, signature, secret, encoding='utf-8'):
    """
    Verify the payload with given signature against given secret
    see https://developer.github.com/webhooks/securing/
    payload: received data as dict
    signature: included SHA1 signature of payload (with secret)
    secret: secret to verify signature
    encoding: encoding for secret (optional)
    """
    h = hmac.new(secret.encode(encoding), payload, hashlib.sha1)
    return hmac.compare_digest('sha1=' + h.hexdigest(), signature)


def process_webhook_push(payload):
    """
    Process webhook event "push"
    payload: event payload
    """
    committee = flask.current_app.config['committee']
    reposlug = ''
    ref = ''
    try:
        ref = payload['ref']
        before = payload['before']
        after = payload['after']
        commits = payload['commits']
        reposlug = payload['repository']['full_name']

        flask.current_app.logger.info(
            f'Received processing push from {reposlug} ({ref}): {before}-{after}'
        )

        for commit in commits:
            committee.process_commit(
                commit_item=commit,
                reposlug=reposlug,
                target_url=flask.request.url
            )

        flask.current_app.logger.info(
            f'Finished processing push from {reposlug} ({ref}): {before}-{after}'
        )
        return 'Issue successfully processed', 200
    except (KeyError, IndexError):
        flask.current_app.logger.info(
            f'Incorrect data entity from IP {flask.request.remote_addr}'
        )
        flask.abort(422, 'Missing required payload fields')
    except Exception:
        flask.current_app.logger.error(
            f'Error occurred while processing {reposlug} ({ref})'
        )
        flask.abort(500, 'Issue processing error')


def process_webhook_ping(payload):
    """
    Process webhook event "ping"
    payload: event payload
    """
    try:
        repo = payload['repository']['full_name']
        hook_id = payload['hook_id']
        flask.current_app.logger.info(
            f'Accepting PING from {repo} (webhook: {hook_id})'
        )
        return 'PONG', 200
    except KeyError:
        flask.current_app.logger.info(
            f'Incorrect data entity from IP {flask.request.remote_addr}'
        )
        flask.abort(422, 'Missing payload contents')


webhook_processors = {
    'push': process_webhook_push,
    'ping': process_webhook_ping
}


committee_blueprint = flask.Blueprint('committee', __name__)


@committee_blueprint.route('/', methods=['GET'])
def index():
    return flask.render_template(
        'index.html.j2',
        cfg=flask.current_app.config['cfg'],
        user=flask.current_app.config['github_user']
    )


@committee_blueprint.route('/', methods=['POST'])
def webhook_listener():
    signature = flask.request.headers.get('X-Hub-Signature', '')
    event = flask.request.headers.get('X-GitHub-Event', '')
    payload = flask.request.get_json()

    secret = flask.current_app.config['cfg'].github_secret

    if secret is not None and not webhook_verify_signature(
            flask.request.data, signature, secret
    ):
        flask.current_app.logger.warning(
            f'Attempt with bad secret from IP {flask.request.remote_addr}'
        )
        flask.abort(401, 'Bad webhook secret')

    if event not in webhook_processors:
        supported = ', '.join(webhook_processors.keys())
        flask.abort(400, f'Event not supported (supported: {supported})')

    return webhook_processors[event](payload)


def create_app(*args, **kwargs):
    app = flask.Flask(__name__)

    app.logger.info('Loading Committee configuration from files')
    cfg = load_config_web(app)

    app.config['cfg'] = cfg
    app.config['committee'] = Committee(
        github=GitHubClient(token=cfg.github_token),
        config=cfg,
        printer=CommitteeLogPrinter(app.logger)
    )

    try:
        app.logger.info('Getting GitHub user using the given token')
        app.config['github_user'] = app.config['committee'].github.user()
    except Exception:
        app.logger.critical('Bad token: could not get GitHub user!')
        exit(1)

    app.register_blueprint(committee_blueprint)
    return app

