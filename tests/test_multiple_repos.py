import pytest
import re

from helper import run, run_ok, config, user


def test_multiple_repos_with_incorrect():
    repo1 = f'{user}/committee-basic'
    repo2 = f'abc'
    cp = run(f'--config "{config("without_rules.cfg")}" '
             f'{repo1} {repo2}')
    assert cp.returncode != 0
    assert (
        f'Error: Invalid value for \'REPOSLUG...\': Reposlug "{repo2}" is not valid!\n' in cp.stderr
    )


@pytest.mark.parametrize('async_flag', ['--async', '--no-async', ''])
def test_multiple_repos(async_flag):
    repo_basic = f'{user}/committee-basic'
    repo_rules = f'{user}/committee-rules'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'{async_flag} --force {repo_basic} {repo_rules}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 30  # 3 lines per commit (4 basic + 6 rules)

    def any_lines_matches(regex):
        return any(map(lambda line: re.match(regex, line) is not None, lines))

    assert any_lines_matches(fr'^- {repo_basic}#[0-9a-f]{{40}}: Removing test file 3$')
    assert any_lines_matches(fr'^- {repo_basic}#[0-9a-f]{{40}}: Update in test file 2$')
    assert any_lines_matches(fr'^- {repo_basic}#[0-9a-f]{{40}}: Add test files$')
    assert any_lines_matches(fr'^- {repo_basic}#[0-9a-f]{{40}}: Add README.md$')

    assert any_lines_matches(fr'^- {repo_rules}#[0-9a-f]{{40}}: My precious lists based on general knowledge$')
    assert any_lines_matches(fr'^- {repo_rules}#[0-9a-f]{{40}}: Fuck off this junk$')
    assert any_lines_matches(fr'^- {repo_rules}#[0-9a-f]{{40}}: Not so much yolo anymore, also yodo$')
    assert any_lines_matches(fr'^- {repo_rules}#[0-9a-f]{{40}}: Add various files$')
    assert any_lines_matches(fr'^- {repo_rules}#[0-9a-f]{{40}}: Add LICENSE$')
    assert any_lines_matches(fr'^- {repo_rules}#[0-9a-f]{{40}}: Initial commit$')
