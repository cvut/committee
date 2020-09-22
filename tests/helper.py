import atexit
import datetime
import os
import pathlib
import requests
import shlex
import subprocess
import sys

fixtures_dir = pathlib.Path(__file__).parent / 'fixtures'
configs_dir = fixtures_dir / 'config'
templates_dir = fixtures_dir / 'config_templates'
wordlists_dir = fixtures_dir / 'wordlists'
run_timestamp = datetime.datetime.now().strftime("%y%m%d-%H%M%S")


def run(line, **kwargs):
    print('$ python committee.py', line)
    command = [sys.executable, 'committee.py'] + shlex.split(line)
    return subprocess.run(command,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          universal_newlines=True,
                          **kwargs)


def run_ok(*args, **kwargs):
    cp = run(*args, **kwargs)
    assert cp.returncode == 0
    assert not cp.stderr
    print(cp.stdout)
    return cp


def config(name):
    return configs_dir / name


try:
    user = os.environ['GH_USER']
    token = os.environ['GH_TOKEN']
except KeyError:
    raise RuntimeError('You must set GH_USER and GH_TOKEN environ vars')
else:
    wordlists = str(wordlists_dir.resolve())
    for source in templates_dir.glob('*.cfg'):
        target = configs_dir / source.name
        target.write_text(
            source.read_text().replace('{REAL_TOKEN}', token).replace('{WORDLISTS_DIR}', wordlists).replace('{TIMESTAMP}', run_timestamp)
        )


def commit_status(repo, ref, context):
    statuses = requests.get(
        f'https://api.github.com/repos/{repo}/commits/{ref}/statuses',
        headers={'Authorization': f'token {token}'},
    ).json()
    for status in statuses:
        if status['context'] == context:
            return status
    return None
