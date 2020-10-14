import pytest

from helper import run, config


def test_no_reposlug():
    """One may forget to provide reposlug argument"""
    cp = run('', entrypoint=True)
    assert cp.returncode != 0
    assert not cp.stdout
    assert (
        'Error: Missing argument \'REPOSLUG\'' in cp.stderr
    )


def test_no_config():
    """One may forget to provide configuration file"""
    cp = run('something/dummy', entrypoint=True)
    assert cp.returncode != 0
    assert not cp.stdout
    assert (
        'Error: Missing option \'-c\' / \'--config\'' in cp.stderr
    )


@pytest.mark.parametrize('config_name', [
    'bogus.cfg',
    'incorrect_path_status.cfg',
    'incorrect_message_match.cfg',
    'incorrect_message_regex.cfg',
    'incorrect_message_wordlist.cfg',
    'incorrect_rule_type.cfg',
    'incorrect_stats_minmax.cfg',
    'incorrect_stats_scope.cfg',
    'incorrect_stats_stat_commit.cfg',
    'incorrect_stats_stat_file.cfg',
    'missing_context.cfg',
    'missing_path_match.cfg',
    'missing_message_match.cfg',
    'missing_rule_text.cfg',
    'missing_stats_max.cfg',
    'missing_stats_stat.cfg',
    'missing_token.cfg',
])
def test_incorrect_config(config_name):
    """And if they don't forget, it still may be incorrect"""
    cp = run(f'--config "{config(config_name)}" '
             f'something/dummy')
    assert cp.returncode != 0
    assert not cp.stdout
    assert (
        'Error: Invalid value for \'-c\' / \'--config\': Failed to load the configuration!' in cp.stderr
    )


@pytest.mark.parametrize('reposlug', [
    'foobar',
    'this/is/too/much',
])
def test_invalid_reposlug(reposlug):
    """Provided reposlug may not actually look like a reposlug"""
    cp = run(f'--config "{config("without_rules.cfg")}" {reposlug}')
    assert cp.returncode != 0
    assert not cp.stdout
    assert (
        f'Error: Invalid value for \'REPOSLUG\': Reposlug "{reposlug}" is not valid!\n' in cp.stderr
    )
