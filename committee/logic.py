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
