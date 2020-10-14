import click
import configparser
import flask
import hashlib
import hmac
import os
import pathlib
import re
import requests
import sys


def flatten(lst):
    return [item for sublist in lst for item in sublist]


class CheckResult:

    def __init__(self, violated, rule_name, message=None, filename=None):
        self.violated = violated
        self.rule_name = rule_name
        self.message = message
        self.filename = filename


class StringMatcher:

    def __init__(self, type):
        self.type = type

    def matches(self, x):
        raise NotImplementedError('Too generic, use a subclass for matching')


class StringMatcherPlain(StringMatcher):

    def __init__(self, word):
        super().__init__(type='plain')
        self.word = word.lower()

    def matches(self, x):
        return self.word in x.lower()


class StringMatcherRegex(StringMatcher):

    def __init__(self, pattern):
        super().__init__(type='regex')
        self.pattern = pattern

    def matches(self, x):
        return self.pattern.match(x) is not None


class StringMatcherWordlist(StringMatcher):

    def __init__(self, filename, words):
        super().__init__(type='wordlist')
        self.filename = filename
        self.words = frozenset(w.lower() for w in words)

    def matches(self, x):
        text = x.lower()
        return any(word in text for word in self.words)


def load_matcher(matcher_spec, config_dir):
    if matcher_spec.startswith('plain:'):
        return StringMatcherPlain(word=matcher_spec[6:])
    if matcher_spec.startswith('regex:'):
        return StringMatcherRegex(pattern=re.compile(matcher_spec[6:], flags=re.IGNORECASE))
    if matcher_spec.startswith('wordlist:'):
        wordlist = filename = pathlib.Path(matcher_spec[9:])
        if not wordlist.is_absolute():
            wordlist = config_dir / wordlist
        with open(wordlist, mode='r') as f:
            lines = f.readlines()
            words = (line.strip() for line in lines if len(line.strip()) > 0)
            return StringMatcherWordlist(filename=filename, words=words)
    raise RuntimeError(f'Unknown match specification "{matcher_spec}"')


class Rule:

    def __init__(self, name, text, type):
        self.name = name
        self.text = text
        self.type = type

    def _make_result_commit(self, matches):
        return CheckResult(
            violated=matches,
            rule_name=self.name,
            message=self.text if matches else None
        )

    def _make_result_file(self, matches, filename):
        return CheckResult(
            violated=matches,
            rule_name=self.name,
            message=self.text.format(filename=filename) if matches else None,
            filename=filename
        )

    def check(self, commit):
        raise NotImplementedError('Too generic, use a subclass for checks')


class RuleMessage(Rule):

    def __init__(self, name: str, text: str, matcher: StringMatcher):
        super().__init__(name, text, 'message')
        self.matcher = matcher

    def check(self, commit):
        matches = self.matcher.matches(commit['commit']['message'])
        return [self._make_result_commit(matches)]

    @staticmethod
    def load(name, text, cfg, section, config_dir):
        return RuleMessage(
            name=name,
            text=text,
            matcher=load_matcher(cfg.get(section, 'match'), config_dir),
        )


class RulePath(Rule):

    STATUSES = ('modified', 'added', 'removed', '*')

    def __init__(self, name, text, status, matcher):
        super().__init__(name, text, 'path')
        self.matcher = matcher
        self.status = status

    def _matches_status(self, status):
        return self.status == '*' or self.status == status

    def _check_file(self, file):
        filename = file['filename']
        matches = self._matches_status(file['status']) and self.matcher.matches(filename)
        return self._make_result_file(matches, filename)

    def check(self, commit):
        return [self._check_file(f) for f in commit['files']]

    @classmethod
    def load(cls, name, text, cfg, section, config_dir):
        status = cfg.get(section, 'status', fallback='*')
        if status not in cls.STATUSES:
            raise RuntimeError(f'Unknown status "{status}" in "{section}"')
        return RulePath(
            name=name,
            text=text,
            status=status,
            matcher=load_matcher(cfg.get(section, 'match'), config_dir),
        )


class RuleStats(Rule):

    SCOPES = ('commit', 'file')
    STATS = {
        'commit': ('total', 'additions', 'deletions'),
        'file': ('changes', 'additions', 'deletions'),
    }

    def __init__(self, name, text, scope, stat, min, max):
        super().__init__(name, text, 'stats')
        self.scope = scope
        self.stat = stat
        self.min = min
        self.max = max
        self._check_min = lambda x: True
        if min is not None:
            self._check_min = lambda x: x >= min
        self._check_max = lambda x: True
        if max is not None:
            self._check_max = lambda x: x <= max

    def _check_number(self, number) -> bool:
        return not (self._check_min(number) and self._check_max(number))

    def _check_commit(self, commit):
        matches = self._check_number(commit['stats'][self.stat])
        return self._make_result_commit(matches)

    def _check_file(self, file):
        matches = self._check_number(file[self.stat])
        return self._make_result_file(matches, file['filename'])

    def check(self, commit):
        if self.scope == 'commit':
            return [self._check_commit(commit)]
        return [self._check_file(f) for f in commit['files']]

    @classmethod
    def load(cls, name, text, cfg, section, **kwargs):
        scope = cfg.get(section, 'scope', fallback='commit')
        stat = cfg.get(section, 'stat')
        if scope not in cls.SCOPES:
            raise RuntimeError(f'Unknown scope "{scope}" in "{section}"')
        if stat not in cls.STATS[scope]:
            raise RuntimeError(f'Unknown stat "{stat}" for scope "{scope}" in "{section}"')
        min_value = cfg.getint(section, 'min', fallback=None)
        max_value = cfg.getint(section, 'max', fallback=None)
        if min_value is None and max_value is None:
            raise RuntimeError(f'Neither min nor max specified in "{section}"')
        return RuleStats(
            name=name,
            text=text,
            scope=scope,
            stat=stat,
            min=min_value,
            max=max_value,
        )


class CommitteeConfig:

    def __init__(self, github_token, context, rules, github_secret=None):
        self.github_token = github_token
        self.github_secret = github_secret
        self.context = context
        self.rules = rules


class ConfigLoader:

    RULES = {
        'message': RuleMessage,
        'path': RulePath,
        'stats': RuleStats,
    }

    @classmethod
    def _load_rule(cls, cfg, section, config_dir):
        name = section[5:]
        text = cfg.get(section, 'text')
        type = cfg.get(section, 'type')
        if type not in cls.RULES.keys():
            raise RuntimeError(f'Unknown rule type "{type}" of "{section}"')
        return cls.RULES[type].load(name, text, cfg, section, config_dir=config_dir)

    @classmethod
    def load(cls, cfg, config_file, web=False):
        config_dir = pathlib.Path(config_file).resolve().parents[0]
        rule_sections = (s for s in cfg.sections() if s.startswith('rule:'))
        config = CommitteeConfig(
            github_token=cfg.get('github', 'token'),
            context=cfg.get('committee', 'context'),
            rules=[cls._load_rule(cfg, section, config_dir) for section in rule_sections],
        )
        if web:
            config.github_secret = cfg.get('github', 'secret', fallback=None)
        return config


class CommitteeResult:

    SUCCESS = 'success'
    FAILURE = 'failure'

    def __init__(self, commit, details):
        self.commit = commit
        self.details = details
        self.violated = set(r.rule_name for r in details if r.violated)
        self.status = self.SUCCESS if len(self.violated) == 0 else self.FAILURE
        if self.status == self.SUCCESS:
            self.description = 'No rules are violated by this commit.'
        else:
            joined = ', '.join(sorted(self.violated))
            self.description = f'The commit violates rules: {joined}.'

    def commit_status(self, config, target_url):
        result = {
            'state': self.status,
            'context': config.context,
            'description': self.description,
        }
        if target_url is not None:
            result['target_url'] = target_url
        return result


class GitHubClient:
    """
    This class can communicate with the GitHub API
    just give it a token and go.
    """
    API = 'https://api.github.com'

    def __init__(self, token, session=None):
        self.token = token
        self.session = session or requests.Session()
        self.session.headers = {'User-Agent': 'committee'}
        self.session.auth = self._token_auth

    def _token_auth(self, req):
        req.headers['Authorization'] = 'token ' + self.token
        return req

    def _paginated_json_get(self, url, params=None):
        r = self.session.get(url=url, params=params)
        r.raise_for_status()
        json = r.json()
        if 'next' in r.links and 'url' in r.links['next']:
            json += self._paginated_json_get(r.links['next']['url'], params)
        return json

    def user(self):
        return self._paginated_json_get(f'{self.API}/user')

    def commits(self, reposlug, params):
        return self.get(url=f'{self.API}/repos/{reposlug}/commits', params=params)

    def statuses(self, reposlug, ref):
        return self.get(url=f'{self.API}/repos/{reposlug}/commits/{ref}/statuses')

    def add_status(self, reposlug, ref, status):
        response = self.session.post(
            url=f'{self.API}/repos/{reposlug}/commits/{ref}/statuses',
            json=status
        )
        response.raise_for_status()
        return response.json()

    def get(self, url: str, params=None):
        return self._paginated_json_get(url=url, params=params)


class CommitteePrinter:

    NONE = 'none'
    COMMITS = 'commits'
    RULES = 'rules'

    def __init__(self, mode, reposlug):
        self.mode = mode
        self.reposlug = reposlug

    @staticmethod
    def _prefix_error():
        click.secho('  => ', bold=True, nl=False)
        click.secho('ERROR', fg='magenta', bold=True, nl=False)
        click.echo(' - ', nl=False)

    @staticmethod
    def _prefix_commit():
        click.echo('- ', nl=False)

    @staticmethod
    def _prefix_status():
        click.echo('  ~> ', nl=False)

    @staticmethod
    def _prefix_result():
        click.secho('  => ', bold=True, nl=False)

    @staticmethod
    def _prefix_rule():
        click.echo('  -> ', nl=False)

    @staticmethod
    def _prefix_rule_sub():
        click.echo('     - ', nl=False)

    def failed_get_commits(self):
        click.secho(f'Failed to retrieve commits from repository {self.reposlug}.', err=True)

    def failed_get_commit(self, commit_item):
        if self.mode == self.NONE:
            return
        sha = commit_item['sha']
        self._prefix_error()
        click.secho(f'Failed to query commit {self.reposlug}#{sha}.', fg='red')

    def get_commit(self, commit):
        if self.mode == self.NONE:
            return
        sha = commit['sha']
        short_message = commit['commit']['message'].splitlines()[0]
        self._prefix_commit()
        click.secho(f'{sha}: {short_message}', bold=True)

    def skipping_commit(self):
        if self.mode == self.NONE:
            return
        self._prefix_result()
        click.secho('SKIPPED', nl=False, fg='yellow')
        click.echo(' - This commit already has status with the same context.')

    def rule_done(self, rule, results):
        if self.mode != self.RULES:
            return
        self._prefix_rule()
        click.echo(f'{rule.name}: ', nl=False)
        is_violated = any(r.violated for r in results)
        if is_violated:
            click.secho('FAIL', fg='red')
        else:
            click.secho('PASS', fg='green')
        for r in results:
            if r.violated:
                self._prefix_rule_sub()
                if r.filename is not None:
                    click.echo(f'{r.filename}: ', nl=False)
                click.echo(r.message)

    def rule_error(self, rule):
        if self.mode != self.RULES:
            return
        self._prefix_rule()
        click.echo(f'{rule.name}: failed to execute')

    def dry_update_status(self):
        if self.mode == self.NONE:
            return
        self._prefix_status()
        click.echo('Updating commit status: ', nl=False)
        click.secho('DRY-RUN', fg='yellow')

    def updated_status(self):
        if self.mode == self.NONE:
            return
        self._prefix_status()
        click.echo('Updating commit status: ', nl=False)
        click.secho('OK', fg='green')

    def failed_update_status(self):
        if self.mode == self.NONE:
            return
        self._prefix_status()
        click.echo('Updating commit status: ', nl=False)
        click.secho('ERROR', fg='magenta')

    def finished(self, result):
        if self.mode == self.NONE:
            return
        self._prefix_result()
        if result.status == CommitteeResult.SUCCESS:
            click.secho('SUCCESS', nl=False, fg='green', bold=True)
        else:
            click.secho('FAILURE', nl=False, fg='red', bold=True)
        click.echo(f' - {result.description}')


class Committee:

    def __init__(self, github, config,  printer):
        self.github = github
        self.config = config
        self.printer = printer

    def _should_skip(self, reposlug, commit):
        statuses = self.github.statuses(reposlug, commit['sha'])
        return self.config.context in (s['context'] for s in statuses)

    def _process_rule(self, commit, rule):
        try:
            results = rule.check(commit)
            self.printer.rule_done(rule, results)
            return results
        except Exception:
            self.printer.rule_error(rule)
            return []

    def _set_commit_status(self, reposlug, result, dry_run, target_url=None):
        if dry_run:
            self.printer.dry_update_status()
            return
        try:
            self.github.add_status(
                reposlug=reposlug,
                ref=result.commit['sha'],
                status=result.commit_status(self.config, target_url),
            )
            self.printer.updated_status()
        except Exception:
            self.printer.failed_update_status()

    def process_commit(self, reposlug, commit_item, dry_run, force, target_url=None):
        self.printer.get_commit(commit_item)
        try:
            commit = self.github.get(commit_item['url'])
            if not force and self._should_skip(reposlug, commit):
                self.printer.skipping_commit()
                return
        except Exception:
            self.printer.failed_get_commit(commit_item)
            return
        results = flatten(
            self._process_rule(commit=commit, rule=rule)
            for rule in sorted(self.config.rules, key=lambda r: r.name)
        )
        result = CommitteeResult(commit=commit, details=results)
        self._set_commit_status(reposlug=reposlug, result=result, dry_run=dry_run, target_url=target_url)
        self.printer.finished(result=result)

    def run(self, reposlug, dry_run, force, params):
        try:
            commits = self.github.commits(reposlug=reposlug, params=params)
            for commit in commits:
                self.process_commit(reposlug=reposlug, commit_item=commit, dry_run=dry_run, force=force)
        except Exception:
            self.printer.failed_get_commits()
            sys.exit(1)


def load_config(ctx, param, value):
    try:
        cfg = configparser.ConfigParser()
        cfg.read_file(value)
        return ConfigLoader.load(cfg, value.name)
    except Exception as e:
        raise click.BadParameter(f'Failed to load the configuration!')


def check_reposlug(ctx, param, value):
    parts = value.split('/')
    if len(parts) != 2:
        raise click.BadParameter(f'Reposlug "{value}" is not valid!')
    return value


FORMATS = [
    CommitteePrinter.NONE,
    CommitteePrinter.COMMITS,
    CommitteePrinter.RULES,
]


@click.command(name='committee')
@click.version_option(version='v0.2')
@click.argument('reposlug', callback=check_reposlug)
@click.option('-c', '--config', type=click.File(mode='r'), callback=load_config,
              help='Committee configuration file.', required=True)
@click.option('-a', '--author', metavar='AUTHOR',
              help='GitHub login or email address of author for checking commits.')
@click.option('-p', '--path', metavar='PATH',
              help='Only commits containing this file path will be checked.')
@click.option('-r', '--ref', metavar='REF',
              help='SHA or branch to check commits from (default is the default branch).')
@click.option('-f', '--force', is_flag=True,
              help='Check even if commit has already status with the same context.')
@click.option('-o', '--output-format', type=click.Choice(FORMATS),
              default=CommitteePrinter.COMMITS, show_default=True,
              help='Verbosity level of the output.')
@click.option('-d', '--dry-run', is_flag=True,
              help='No changes will be made on GitHub.')
def main(reposlug, config: CommitteeConfig, author, path, ref, force, output_format, dry_run):
    """An universal tool for checking commits on GitHub"""
    github = GitHubClient(token=config.github_token)
    committee = Committee(
        github=github,
        config=config,
        printer=CommitteePrinter(mode=output_format, reposlug=reposlug)
    )
    params = {
        'author': author,
        'path': path,
        'sha': ref,
    }
    committee.run(
        reposlug=reposlug,
        dry_run=dry_run,
        force=force,
        params={k: v for k, v in params.items() if v is not None}
    )


if __name__ == '__main__':
    main()

###############################################################################
# Web


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
