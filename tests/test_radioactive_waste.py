from helper import run_ok, config, user, commit_status


def test_radioactive_waste():
    """Tests whether it can handle more than 100 commits"""
    repo = f'{user}/committee-radioactive'
    cp = run_ok(f'--config "{config("without_rules.cfg")}" '
                f'--force --dry-run {repo}'
                )

    for i in range(1, 112):
        assert f'Waste number {i}' in cp.stdout
