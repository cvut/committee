import re

from helper import run

hlp_m = run('--help')
hlp_e = run('--help', entrypoint=True)
stdout_m = hlp_m.stdout
stdout_e = hlp_e.stdout


def test_usage():
    # tip: use cli(prog_name='committee') when calling the click.command function
    assert stdout_m.startswith('Usage: committee [OPTIONS] REPOSLUG')


def test_description():
    description = 'An universal tool for checking commits on GitHub'
    assert description in stdout_m
    assert description in stdout_e


def test_output_format_option():
    for stdout in stdout_m, stdout_e:
        assert re.search(r'-o,\s+--output-format\s+\[none\|commits\|rules\]\s+'
                         r'Verbosity\s+level\s+of\s+the\s+output\.\s+\[default:\s+commits\]', stdout)


def test_path_option():
    for stdout in stdout_m, stdout_e:
        assert re.search(r'-p,\s+--path\s+PATH\s+'
                         r'Only\s+commits\s+containing\s+this\s+file\s+path\s+will\s+be\s+checked\.',
                         stdout)


def test_ref_option():
    for stdout in stdout_m, stdout_e:
        assert re.search(r'-r,\s+--ref\s+REF\s+'
                         r'SHA\s+or\s+branch\s+to\s+check\s+commits\s+from\s+\(default\s+is\s+the\s+default\s+branch\)\.',
                         stdout)


def test_author_option():
    for stdout in stdout_m, stdout_e:
        assert re.search(r'-a,\s+--author\s+AUTHOR\s+'
                         r'GitHub\s+login\s+or\s+email\s+address\s+of\s+author\s+for\s+checking\s+commits\.',
                         stdout)


def test_force_flag():
    for stdout in stdout_m, stdout_e:
        assert re.search(r'-f,\s+--force\s+'
                         r'Check\s+even\s+if\s+commit\s+has\s+already\s+status\s+with\s+the\s+same\s+context\.',
                         stdout)


def test_dry_run_flag():
    for stdout in stdout_m, stdout_e:
        assert re.search(r'-d,\s+--dry-run\s+'
                         r'No\s+changes\s+will\s+be\s+made\s+on\s+GitHub\.',
                         stdout)


def test_config_option():
    for stdout in stdout_m, stdout_e:
        assert re.search(r'-c,\s+--config\s+FILENAME\s+'
                         r'Committee\s+configuration\s+file\.',
                         stdout)


def test_version():
    for stdout in stdout_m, stdout_e:
        assert re.search(r'--version\s+'
                         r'Show the version and exit\.',
                         stdout)
