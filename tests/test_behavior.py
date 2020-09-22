import re
import time

from helper import run, run_ok, config, user, run_timestamp, commit_status


def test_nonexistent_repo():
    cp = run(f'--config "{config("without_rules.cfg")}" '
             f'MarekSuchanek/does-not-exist-cause-dummy')
    assert cp.returncode == 1
    assert not cp.stdout
    assert (
        'Failed to retrieve commits from repository MarekSuchanek/does-not-exist-cause-dummy.' in cp.stderr
    )


def test_without_rules():
    repo = f'{user}/committee-basic'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--force {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 12  # 3 lines per commit

    assert re.match(r'^- [0-9a-f]{40}: Removing test file 3$', lines[0]) is not None
    assert lines[1] == '  ~> Updating commit status: OK'
    assert lines[2] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Update in test file 2$', lines[3]) is not None
    assert lines[4] == '  ~> Updating commit status: OK'
    assert lines[5] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add test files$', lines[6]) is not None
    assert lines[7] == '  ~> Updating commit status: OK'
    assert lines[8] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add README.md$', lines[9]) is not None
    assert lines[10] == '  ~> Updating commit status: OK'
    assert lines[11] == '  => SUCCESS - No rules are violated by this commit.'


def test_branch():
    repo = f'{user}/committee-basic'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--force --ref other {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 6  # 3 lines per commit

    assert re.match(r'^- [0-9a-f]{40}: Add branch note$', lines[0]) is not None
    assert re.match(r'^- [0-9a-f]{40}: Add README.md$', lines[3]) is not None


def test_path():
    repo = f'{user}/committee-basic'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--force --path "test/file2" {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 6  # 3 lines per commit

    assert re.match(r'^- [0-9a-f]{40}: Update in test file 2$', lines[0]) is not None
    assert re.match(r'^- [0-9a-f]{40}: Add test files$', lines[3]) is not None


def test_author():
    repo = f'MarekSuchanek/committee-others'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--force --dry-run --author MarekSuchanek {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 3  # 3 lines per commit

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[0]) is not None


def test_status_update_success():
    tag = 'xyz'
    context = f'committee/basic_success_{run_timestamp}'
    repo = f'{user}/committee-basic'
    cp = run_ok(f'--config "{config("basic_success.cfg")}" '
                f'--ref feature/xyz {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 6  # 3 lines per commit

    assert re.match(r'^- [0-9a-f]{40}: Add XYZ feature$', lines[0]) is not None
    assert '  ~> Updating commit status: OK' == lines[1]
    assert '  => SUCCESS - No rules are violated by this commit.' == lines[2]

    status = commit_status(repo, tag, context)
    assert status is not None
    assert status['state'] == 'success'
    assert status['description'] == 'No rules are violated by this commit.'


def test_status_update_failure():
    tag = 'xyz'
    context = f'committee/basic_failure_{run_timestamp}'
    repo = f'{user}/committee-basic'
    cp = run_ok(f'--config "{config("basic_failure.cfg")}" '
                f'--ref feature/xyz {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 6  # 3 lines per commit

    assert re.match(r'^- [0-9a-f]{40}: Add XYZ feature$', lines[0]) is not None
    assert '  ~> Updating commit status: OK' == lines[1]
    assert '  => FAILURE - The commit violates rules: any-message.' == lines[2]

    status = commit_status(repo, tag, context)
    assert status is not None
    assert status['state'] == 'failure'
    assert status['description'] == 'The commit violates rules: any-message.'


def test_update_foreign():
    repo = 'committee-test/forbidden-repo'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--force {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 3  # 3 lines per commit

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[0]) is not None
    assert '  ~> Updating commit status: ERROR' == lines[1]
    assert '  => SUCCESS - No rules are violated by this commit.' == lines[2]


def test_dryrun_foreign():
    repo = 'committee-test/forbidden-repo'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--dry-run {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 3  # 3 lines per commit

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[0]) is not None
    assert '  ~> Updating commit status: DRY-RUN' == lines[1]
    assert '  => SUCCESS - No rules are violated by this commit.' == lines[2]


def test_dryrun_own():
    tag = 'abc'
    context = f'committee/basic_success_{run_timestamp}'
    repo = f'{user}/committee-basic'
    cp = run_ok(f'--config "{config("basic_success.cfg")}" '
                f'--dry-run --force --ref feature/abc {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 6  # 3 lines per commit

    assert re.match(r'^- [0-9a-f]{40}: Add ABC feature$', lines[0]) is not None
    assert '  ~> Updating commit status: DRY-RUN' == lines[1]
    assert '  => SUCCESS - No rules are violated by this commit.' == lines[2]

    status = commit_status(repo, tag, context)
    assert status is None


def test_skipping():
    tag = 'abc'
    context = f'committee/basic_skipping'
    repo = f'{user}/committee-basic'
    # May the Force be with you... always (ensure the status)
    cp = run_ok(f'--config "{config("basic_skipping.cfg")}" '
                f'--force --ref feature/abc {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 6  # 3 lines per commit
    assert re.match(r'^- [0-9a-f]{40}: Add ABC feature$', lines[0]) is not None
    assert '  ~> Updating commit status: OK' == lines[1]
    assert '  => SUCCESS - No rules are violated by this commit.' == lines[2]

    first_status = commit_status(repo, tag, context)
    assert first_status is not None

    # Ensure that timestamp would not match...
    time.sleep(1)

    # Now again without using the Force
    cp = run_ok(f'--config "{config("basic_skipping.cfg")}" '
                f'--ref feature/abc {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 4  # 2 lines per commit (both skipped)
    assert re.match(r'^- [0-9a-f]{40}: Add ABC feature$', lines[0]) is not None
    assert '  => SKIPPED - This commit already has status with the same context.' == lines[1]

    second_status = commit_status(repo, tag, context)
    assert first_status is not None
    assert first_status['updated_at'] == second_status['updated_at']

    # Ensure that timestamp would not match...
    time.sleep(1)

    # Now again without using the Force
    cp = run_ok(f'--config "{config("basic_skipping.cfg")}" '
                f'--force --ref feature/abc {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 6  # 3 lines per commit
    assert re.match(r'^- [0-9a-f]{40}: Add ABC feature$', lines[0]) is not None
    assert '  ~> Updating commit status: OK' == lines[1]
    assert '  => SUCCESS - No rules are violated by this commit.' == lines[2]

    third_status = commit_status(repo, tag, context)
    assert first_status is not None
    assert first_status['updated_at'] != third_status['updated_at']


def test_message_plain():
    repo = f'{user}/committee-rules'
    cp = run_ok(f'--config "{config("message_plain.cfg")}" '
                f'--force --dry-run --output-format rules {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 32  # 6 commits, 2 rules -> 5 lines per commit, +2 violations

    assert re.match(r'^- [0-9a-f]{40}: My precious lists', lines[0]) is not None
    assert lines[1] == '  -> commit-in-commit: PASS'
    assert lines[2] == '  -> vague: PASS'
    assert lines[3] == '  ~> Updating commit status: DRY-RUN'
    assert lines[4] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Fuck off this junk$', lines[5]) is not None
    assert lines[6] == '  -> commit-in-commit: PASS'
    assert lines[7] == '  -> vague: PASS'
    assert lines[8] == '  ~> Updating commit status: DRY-RUN'
    assert lines[9] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Not so much yolo anymore, also yodo$', lines[10]) is not None
    assert lines[11] == '  -> commit-in-commit: PASS'
    assert lines[12] == '  -> vague: PASS'
    assert lines[13] == '  ~> Updating commit status: DRY-RUN'
    assert lines[14] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add various files$', lines[15]) is not None
    assert lines[16] == '  -> commit-in-commit: PASS'
    assert lines[17] == '  -> vague: FAIL'
    assert lines[18] == '     - The commit message is vague.'
    assert lines[19] == '  ~> Updating commit status: DRY-RUN'
    assert lines[20] == '  => FAILURE - The commit violates rules: vague.'

    assert re.match(r'^- [0-9a-f]{40}: Add LICENSE$', lines[21]) is not None
    assert lines[22] == '  -> commit-in-commit: PASS'
    assert lines[23] == '  -> vague: PASS'
    assert lines[24] == '  ~> Updating commit status: DRY-RUN'
    assert lines[25] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[26]) is not None
    assert lines[27] == '  -> commit-in-commit: FAIL'
    assert lines[28] == '     - Everyone already knows that this is a commit...'
    assert lines[29] == '  -> vague: PASS'
    assert lines[30] == '  ~> Updating commit status: DRY-RUN'
    assert lines[31] == '  => FAILURE - The commit violates rules: commit-in-commit.'


def test_message_regex():
    repo = f'{user}/committee-rules'
    cp = run_ok(f'-c "{config("message_regex.cfg")}" '
                f'-f -d -o rules {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 39  # 6 commits, 3 rules -> 6 lines per commit, +3 violations

    assert re.match(r'^- [0-9a-f]{40}: My precious lists', lines[0]) is not None
    assert lines[1] == '  -> file-or-files: PASS'
    assert lines[2] == '  -> junk-in-the-end: PASS'
    assert lines[3] == '  -> too-short-message: PASS'
    assert lines[4] == '  ~> Updating commit status: DRY-RUN'
    assert lines[5] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Fuck off this junk$', lines[6]) is not None
    assert lines[ 7] == '  -> file-or-files: PASS'
    assert lines[ 8] == '  -> junk-in-the-end: FAIL'
    assert lines[ 9] == '     - The message ends with junk.'
    assert lines[10] == '  -> too-short-message: PASS'
    assert lines[11] == '  ~> Updating commit status: DRY-RUN'
    assert lines[12] == '  => FAILURE - The commit violates rules: junk-in-the-end.'

    assert re.match(r'^- [0-9a-f]{40}: Not so much yolo anymore, also yodo$', lines[13]) is not None
    assert lines[14] == '  -> file-or-files: PASS'
    assert lines[15] == '  -> junk-in-the-end: PASS'
    assert lines[16] == '  -> too-short-message: PASS'
    assert lines[17] == '  ~> Updating commit status: DRY-RUN'
    assert lines[18] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add various files$', lines[19]) is not None
    assert lines[20] == '  -> file-or-files: FAIL'
    assert lines[21] == '     - Yah, certainly there are some files...'
    assert lines[22] == '  -> junk-in-the-end: PASS'
    assert lines[23] == '  -> too-short-message: PASS'
    assert lines[24] == '  ~> Updating commit status: DRY-RUN'
    assert lines[25] == '  => FAILURE - The commit violates rules: file-or-files.'

    assert re.match(r'^- [0-9a-f]{40}: Add LICENSE$', lines[26]) is not None
    assert lines[27] == '  -> file-or-files: PASS'
    assert lines[28] == '  -> junk-in-the-end: PASS'
    assert lines[29] == '  -> too-short-message: FAIL'
    assert lines[30] == '     - The message is way too short.'
    assert lines[31] == '  ~> Updating commit status: DRY-RUN'
    assert lines[32] == '  => FAILURE - The commit violates rules: too-short-message.'

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[33]) is not None
    assert lines[34] == '  -> file-or-files: PASS'
    assert lines[35] == '  -> junk-in-the-end: PASS'
    assert lines[36] == '  -> too-short-message: PASS'
    assert lines[37] == '  ~> Updating commit status: DRY-RUN'
    assert lines[38] == '  => SUCCESS - No rules are violated by this commit.'


def test_message_wordlist():
    repo = f'{user}/committee-rules'
    cp = run_ok(f'-c "{config("message_wordlist.cfg")}" '
                f'-f -d -o rules {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 42  # 6 commits, 3 rules -> 6 lines per commit, +6 violations

    assert re.match(r'^- [0-9a-f]{40}: My precious lists', lines[0]) is not None
    assert lines[1] == '  -> absolutely-forbidden: PASS'
    assert lines[2] == '  -> no-dummies: PASS'
    assert lines[3] == '  -> relatively-forbidden: PASS'
    assert lines[4] == '  ~> Updating commit status: DRY-RUN'
    assert lines[5] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Fuck off this junk$', lines[6]) is not None
    assert lines[ 7] == '  -> absolutely-forbidden: FAIL'
    assert lines[ 8] == '     - Such message is absolutely forbidden.'
    assert lines[ 9] == '  -> no-dummies: FAIL'
    assert lines[10] == '     - The message contains dummy word(s).'
    assert lines[11] == '  -> relatively-forbidden: FAIL'
    assert lines[12] == '     - There are some relatively forbidden words in the message.'
    assert lines[13] == '  ~> Updating commit status: DRY-RUN'
    assert lines[14] == '  => FAILURE - The commit violates rules: absolutely-forbidden, no-dummies, relatively-forbidden.'

    assert re.match(r'^- [0-9a-f]{40}: Not so much yolo anymore, also yodo$', lines[15]) is not None
    assert lines[16] == '  -> absolutely-forbidden: PASS'
    assert lines[17] == '  -> no-dummies: FAIL'
    assert lines[18] == '     - The message contains dummy word(s).'
    assert lines[19] == '  -> relatively-forbidden: PASS'
    assert lines[20] == '  ~> Updating commit status: DRY-RUN'
    assert lines[21] == '  => FAILURE - The commit violates rules: no-dummies.'

    assert re.match(r'^- [0-9a-f]{40}: Add various files$', lines[22]) is not None
    assert lines[23] == '  -> absolutely-forbidden: PASS'
    assert lines[24] == '  -> no-dummies: PASS'
    assert lines[25] == '  -> relatively-forbidden: PASS'
    assert lines[26] == '  ~> Updating commit status: DRY-RUN'
    assert lines[27] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add LICENSE$', lines[28]) is not None
    assert lines[29] == '  -> absolutely-forbidden: PASS'
    assert lines[30] == '  -> no-dummies: PASS'
    assert lines[31] == '  -> relatively-forbidden: PASS'
    assert lines[32] == '  ~> Updating commit status: DRY-RUN'
    assert lines[33] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[34]) is not None
    assert lines[35] == '  -> absolutely-forbidden: FAIL'
    assert lines[36] == '     - Such message is absolutely forbidden.'
    assert lines[37] == '  -> no-dummies: PASS'
    assert lines[38] == '  -> relatively-forbidden: FAIL'
    assert lines[39] == '     - There are some relatively forbidden words in the message.'
    assert lines[40] == '  ~> Updating commit status: DRY-RUN'
    assert lines[41] == '  => FAILURE - The commit violates rules: absolutely-forbidden, relatively-forbidden.'


def test_path_plain():
    repo = f'{user}/committee-rules'
    cp = run_ok(f'-c "{config("path_plain.cfg")}" '
                f'-f -d -o rules {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 41  # 6 commits, 3 rules -> 6 lines per commit, +5 violations

    assert re.match(r'^- [0-9a-f]{40}: My precious lists', lines[0]) is not None
    assert lines[1] == '  -> no-lists: FAIL'
    assert lines[2] == '     - lists/blacklist.txt: Publishing lists is potentially dangerous.'
    assert lines[3] == '     - lists/whitelist.txt: Publishing lists is potentially dangerous.'
    assert lines[4] == '  -> no-shits: PASS'
    assert lines[5] == '  -> touching: PASS'
    assert lines[6] == '  ~> Updating commit status: DRY-RUN'
    assert lines[7] == '  => FAILURE - The commit violates rules: no-lists.'

    assert re.match(r'^- [0-9a-f]{40}: Fuck off this junk$', lines[8]) is not None
    assert lines[ 9] == '  -> no-lists: PASS'
    assert lines[10] == '  -> no-shits: FAIL'
    assert lines[11] == '     - topshit.txt: There is something shitty.'
    assert lines[12] == '  -> touching: PASS'
    assert lines[13] == '  ~> Updating commit status: DRY-RUN'
    assert lines[14] == '  => FAILURE - The commit violates rules: no-shits.'

    assert re.match(r'^- [0-9a-f]{40}: Not so much yolo anymore, also yodo$', lines[15]) is not None
    assert lines[16] == '  -> no-lists: PASS'
    assert lines[17] == '  -> no-shits: PASS'
    assert lines[18] == '  -> touching: PASS'
    assert lines[19] == '  ~> Updating commit status: DRY-RUN'
    assert lines[20] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add various files$', lines[21]) is not None
    assert lines[22] == '  -> no-lists: PASS'
    assert lines[23] == '  -> no-shits: FAIL'
    assert lines[24] == '     - topshit.txt: There is something shitty.'
    assert lines[25] == '  -> touching: FAIL'
    assert lines[26] == '     - cant-touch-this: Touching is forbidden as it evokes sexual harassment.'
    assert lines[27] == '  ~> Updating commit status: DRY-RUN'
    assert lines[28] == '  => FAILURE - The commit violates rules: no-shits, touching.'

    assert re.match(r'^- [0-9a-f]{40}: Add LICENSE$', lines[29]) is not None
    assert lines[30] == '  -> no-lists: PASS'
    assert lines[31] == '  -> no-shits: PASS'
    assert lines[32] == '  -> touching: PASS'
    assert lines[33] == '  ~> Updating commit status: DRY-RUN'
    assert lines[34] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[35]) is not None
    assert lines[36] == '  -> no-lists: PASS'
    assert lines[37] == '  -> no-shits: PASS'
    assert lines[38] == '  -> touching: PASS'
    assert lines[39] == '  ~> Updating commit status: DRY-RUN'
    assert lines[40] == '  => SUCCESS - No rules are violated by this commit.'


def test_path_modified_plain():
    repo = f'{user}/committee-rules'
    cp = run_ok(f'-c "{config("path_modified_plain.cfg")}" '
                f'-f -d -o rules {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 25  # 6 commits, 1 rules -> 4 lines per commit, +1 violations

    assert re.match(r'^- [0-9a-f]{40}: My precious lists', lines[0]) is not None
    assert lines[1] == '  -> rigid-yolo: PASS'
    assert lines[2] == '  ~> Updating commit status: DRY-RUN'
    assert lines[3] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Fuck off this junk$', lines[4]) is not None
    assert lines[5] == '  -> rigid-yolo: PASS'
    assert lines[6] == '  ~> Updating commit status: DRY-RUN'
    assert lines[7] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Not so much yolo anymore, also yodo$', lines[8]) is not None
    assert lines[ 9] == '  -> rigid-yolo: FAIL'
    assert lines[10] == '     - yolo.txt: YOLO must not be modified.'
    assert lines[11] == '  ~> Updating commit status: DRY-RUN'
    assert lines[12] == '  => FAILURE - The commit violates rules: rigid-yolo.'

    assert re.match(r'^- [0-9a-f]{40}: Add various files$', lines[13]) is not None
    assert lines[14] == '  -> rigid-yolo: PASS'
    assert lines[15] == '  ~> Updating commit status: DRY-RUN'
    assert lines[16] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add LICENSE$', lines[17]) is not None
    assert lines[18] == '  -> rigid-yolo: PASS'
    assert lines[19] == '  ~> Updating commit status: DRY-RUN'
    assert lines[20] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[21]) is not None
    assert lines[22] == '  -> rigid-yolo: PASS'
    assert lines[23] == '  ~> Updating commit status: DRY-RUN'
    assert lines[24] == '  => SUCCESS - No rules are violated by this commit.'


def test_path_removed_regex():
    repo = f'{user}/committee-rules'
    cp = run_ok(f'-c "{config("path_removed_regex.cfg")}" '
                f'-f -d -o rules {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 34  # 6 commits, 2 rules -> 5 lines per commit, +4 violations

    assert re.match(r'^- [0-9a-f]{40}: My precious lists', lines[0]) is not None
    assert lines[1] == '  -> love-txt: PASS'
    assert lines[2] == '  -> persist-readme: PASS'
    assert lines[3] == '  ~> Updating commit status: DRY-RUN'
    assert lines[4] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Fuck off this junk$', lines[5]) is not None
    assert lines[ 6] == '  -> love-txt: FAIL'
    assert lines[ 7] == '     - dummy.txt: Why are you deleting text files? Those are so useful!'
    assert lines[ 8] == '     - topshit.txt: Why are you deleting text files? Those are so useful!'
    assert lines[ 9] == '     - yolo.txt: Why are you deleting text files? Those are so useful!'
    assert lines[10] == '  -> persist-readme: FAIL'
    assert lines[11] == '     - README.md: README is important, do not delete it.'
    assert lines[12] == '  ~> Updating commit status: DRY-RUN'
    assert lines[13] == '  => FAILURE - The commit violates rules: love-txt, persist-readme.'

    assert re.match(r'^- [0-9a-f]{40}: Not so much yolo anymore, also yodo$', lines[14]) is not None
    assert lines[15] == '  -> love-txt: PASS'
    assert lines[16] == '  -> persist-readme: PASS'
    assert lines[17] == '  ~> Updating commit status: DRY-RUN'
    assert lines[18] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add various files$', lines[19]) is not None
    assert lines[20] == '  -> love-txt: PASS'
    assert lines[21] == '  -> persist-readme: PASS'
    assert lines[22] == '  ~> Updating commit status: DRY-RUN'
    assert lines[23] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add LICENSE$', lines[24]) is not None
    assert lines[25] == '  -> love-txt: PASS'
    assert lines[26] == '  -> persist-readme: PASS'
    assert lines[27] == '  ~> Updating commit status: DRY-RUN'
    assert lines[28] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[29]) is not None
    assert lines[30] == '  -> love-txt: PASS'
    assert lines[31] == '  -> persist-readme: PASS'
    assert lines[32] == '  ~> Updating commit status: DRY-RUN'
    assert lines[33] == '  => SUCCESS - No rules are violated by this commit.'


def test_path_added_wordlist():
    repo = f'{user}/committee-rules'
    cp = run_ok(f'-c "{config("path_added_wordlist.cfg")}" '
                f'-f -d -o rules {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 34  # 6 commits, 2 rules -> 5 lines per commit, +4 violations

    assert re.match(r'^- [0-9a-f]{40}: My precious lists', lines[0]) is not None
    assert lines[1] == '  -> absolute-dummy: PASS'
    assert lines[2] == '  -> racist-colors: FAIL'
    assert lines[3] == '     - lists/blacklist.txt: Some colors are not allowed... avoid using colors at all.'
    assert lines[4] == '     - lists/whitelist.txt: Some colors are not allowed... avoid using colors at all.'
    assert lines[5] == '  ~> Updating commit status: DRY-RUN'
    assert lines[6] == '  => FAILURE - The commit violates rules: racist-colors.'

    assert re.match(r'^- [0-9a-f]{40}: Fuck off this junk$', lines[7]) is not None
    assert lines[ 8] == '  -> absolute-dummy: PASS'
    assert lines[ 9] == '  -> racist-colors: PASS'
    assert lines[10] == '  ~> Updating commit status: DRY-RUN'
    assert lines[11] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Not so much yolo anymore, also yodo$', lines[12]) is not None
    assert lines[13] == '  -> absolute-dummy: PASS'
    assert lines[14] == '  -> racist-colors: PASS'
    assert lines[15] == '  ~> Updating commit status: DRY-RUN'
    assert lines[16] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Add various files$', lines[17]) is not None
    assert lines[18] == '  -> absolute-dummy: FAIL'
    assert lines[19] == '     - dummy.txt: Something dummy in filename detected.'
    assert lines[20] == '     - yolo.txt: Something dummy in filename detected.'
    assert lines[21] == '  -> racist-colors: PASS'
    assert lines[22] == '  ~> Updating commit status: DRY-RUN'
    assert lines[23] == '  => FAILURE - The commit violates rules: absolute-dummy.'

    assert re.match(r'^- [0-9a-f]{40}: Add LICENSE$', lines[24]) is not None
    assert lines[25] == '  -> absolute-dummy: PASS'
    assert lines[26] == '  -> racist-colors: PASS'
    assert lines[27] == '  ~> Updating commit status: DRY-RUN'
    assert lines[28] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[29]) is not None
    assert lines[30] == '  -> absolute-dummy: PASS'
    assert lines[31] == '  -> racist-colors: PASS'
    assert lines[32] == '  ~> Updating commit status: DRY-RUN'
    assert lines[33] == '  => SUCCESS - No rules are violated by this commit.'


def test_stats_commit():
    repo = f'{user}/committee-rules'
    cp = run_ok(f'-c "{config("stats_commit.cfg")}" '
                f'-f -d -o rules {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 43  # 6 commits, 3 rules -> 6 lines per commit, +7 violations

    # {'total': 4, 'additions': 4, 'deletions': 0}
    assert re.match(r'^- [0-9a-f]{40}: My precious lists', lines[0]) is not None
    assert lines[1] == '  -> collateral-damage: PASS'
    assert lines[2] == '  -> nothing-new: PASS'
    assert lines[3] == '  -> satan-incoming: FAIL'
    assert lines[4] == '     - Seems like you don\'t want to summon Satan.'
    assert lines[5] == '  ~> Updating commit status: DRY-RUN'
    assert lines[6] == '  => FAILURE - The commit violates rules: satan-incoming.'

    # {'total': 671, 'additions': 0, 'deletions': 671}
    assert re.match(r'^- [0-9a-f]{40}: Fuck off this junk$', lines[7]) is not None
    assert lines[ 8] == '  -> collateral-damage: FAIL'
    assert lines[ 9] == '     - Too many things lost in the commit.'
    assert lines[10] == '  -> nothing-new: FAIL'
    assert lines[11] == '     - Commit should add at least something new.'
    assert lines[12] == '  -> satan-incoming: FAIL'
    assert lines[13] == '     - Seems like you don\'t want to summon Satan.'
    assert lines[14] == '  ~> Updating commit status: DRY-RUN'
    assert lines[15] == '  => FAILURE - The commit violates rules: collateral-damage, nothing-new, satan-incoming.'

    # {'total': 666, 'additions': 333, 'deletions': 333}
    assert re.match(r'^- [0-9a-f]{40}: Not so much yolo anymore, also yodo$', lines[16]) is not None
    assert lines[17] == '  -> collateral-damage: PASS'
    assert lines[18] == '  -> nothing-new: PASS'
    assert lines[19] == '  -> satan-incoming: PASS'
    assert lines[20] == '  ~> Updating commit status: DRY-RUN'
    assert lines[21] == '  => SUCCESS - No rules are violated by this commit.'

    # {'total': 668, 'additions': 668, 'deletions': 0}
    assert re.match(r'^- [0-9a-f]{40}: Add various files$', lines[22]) is not None
    assert lines[23] == '  -> collateral-damage: PASS'
    assert lines[24] == '  -> nothing-new: PASS'
    assert lines[25] == '  -> satan-incoming: FAIL'
    assert lines[26] == '     - Seems like you don\'t want to summon Satan.'
    assert lines[27] == '  ~> Updating commit status: DRY-RUN'
    assert lines[28] == '  => FAILURE - The commit violates rules: satan-incoming.'

    # {'total': 1, 'additions': 1, 'deletions': 0}
    assert re.match(r'^- [0-9a-f]{40}: Add LICENSE$', lines[29]) is not None
    assert lines[30] == '  -> collateral-damage: PASS'
    assert lines[31] == '  -> nothing-new: PASS'
    assert lines[32] == '  -> satan-incoming: FAIL'
    assert lines[33] == '     - Seems like you don\'t want to summon Satan.'
    assert lines[34] == '  ~> Updating commit status: DRY-RUN'
    assert lines[35] == '  => FAILURE - The commit violates rules: satan-incoming.'

    # {'total': 3, 'additions': 3, 'deletions': 0}
    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[36]) is not None
    assert lines[37] == '  -> collateral-damage: PASS'
    assert lines[38] == '  -> nothing-new: PASS'
    assert lines[39] == '  -> satan-incoming: FAIL'
    assert lines[40] == '     - Seems like you don\'t want to summon Satan.'
    assert lines[41] == '  ~> Updating commit status: DRY-RUN'
    assert lines[42] == '  => FAILURE - The commit violates rules: satan-incoming.'


def test_stats_file():
    repo = f'{user}/committee-rules'
    cp = run_ok(f'-c "{config("stats_file.cfg")}" '
                f'-f -d -o rules {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 38  # 6 commits, 2 rules -> 5 lines per commit, +8 violations

    assert re.match(r'^- [0-9a-f]{40}: My precious lists', lines[0]) is not None
    assert lines[1] == '  -> many-changes: PASS'
    assert lines[2] == '  -> nothing-new: PASS'
    assert lines[3] == '  ~> Updating commit status: DRY-RUN'
    assert lines[4] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Fuck off this junk$', lines[5]) is not None
    assert lines[ 6] == '  -> many-changes: FAIL'
    assert lines[ 7] == '     - yolo.txt: Too many changes in the file.'
    assert lines[ 8] == '  -> nothing-new: FAIL'
    assert lines[ 9] == '     - README.md: The file is changed but adds nothing new.'
    assert lines[10] == '     - dummy.txt: The file is changed but adds nothing new.'
    assert lines[11] == '     - topshit.txt: The file is changed but adds nothing new.'
    assert lines[12] == '     - yolo.txt: The file is changed but adds nothing new.'
    assert lines[13] == '  ~> Updating commit status: DRY-RUN'
    assert lines[14] == '  => FAILURE - The commit violates rules: many-changes, nothing-new.'

    assert re.match(r'^- [0-9a-f]{40}: Not so much yolo anymore, also yodo$', lines[15]) is not None
    assert lines[16] == '  -> many-changes: FAIL'
    assert lines[17] == '     - yolo.txt: Too many changes in the file.'
    assert lines[18] == '  -> nothing-new: PASS'
    assert lines[19] == '  ~> Updating commit status: DRY-RUN'
    assert lines[20] == '  => FAILURE - The commit violates rules: many-changes.'

    assert re.match(r'^- [0-9a-f]{40}: Add various files$', lines[21]) is not None
    assert lines[22] == '  -> many-changes: FAIL'
    assert lines[23] == '     - yolo.txt: Too many changes in the file.'
    assert lines[24] == '  -> nothing-new: FAIL'
    assert lines[25] == '     - cant-touch-this: The file is changed but adds nothing new.'
    assert lines[26] == '  ~> Updating commit status: DRY-RUN'
    assert lines[27] == '  => FAILURE - The commit violates rules: many-changes, nothing-new.'

    assert re.match(r'^- [0-9a-f]{40}: Add LICENSE$', lines[28]) is not None
    assert lines[29] == '  -> many-changes: PASS'
    assert lines[30] == '  -> nothing-new: PASS'
    assert lines[31] == '  ~> Updating commit status: DRY-RUN'
    assert lines[32] == '  => SUCCESS - No rules are violated by this commit.'

    assert re.match(r'^- [0-9a-f]{40}: Initial commit$', lines[33]) is not None
    assert lines[34] == '  -> many-changes: PASS'
    assert lines[35] == '  -> nothing-new: PASS'
    assert lines[36] == '  ~> Updating commit status: DRY-RUN'
    assert lines[37] == '  => SUCCESS - No rules are violated by this commit.'


def test_commits_output_basic():
    repo = f'{user}/committee-basic'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--force --output-format commits {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 12


def test_no_output_basic():
    repo = f'{user}/committee-basic'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--force --output-format none {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 0  # nothing when mode is none


def test_no_output_foreign():
    repo = 'committee-test/forbidden-repo'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--force --output-format none {repo}')
    lines = cp.stdout.splitlines()

    assert len(lines) == 0  # nothing when mode is none
