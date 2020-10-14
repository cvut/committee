import os


def test_submodules(utils, tmpdir):
    tmpdir.chdir()  # Work in separate tmp dir

    repo_dir = 'repo'
    # Prepare venv and clone repository to repo dir
    utils.clone_repo_with_fresh_venv(repo_dir)

    # Check the content of repository (Python module "committee")
    content = os.listdir(str(tmpdir.join(repo_dir)))
    assert 'committee' in content, \
        'No "committee" entry in the repository'

    assert os.path.isdir(str(tmpdir.join(repo_dir).join('committee'))), \
        'Entry "committee" is not a directory'

    content = os.listdir(str(tmpdir.join(repo_dir).join('committee')))

    assert '__init__.py' in content, \
        'committee is not a module (no __init__.py file)'
    assert '__main__.py' in content, \
        'committee is not runnable (no __main__.py file)'
    pyfiles = [f for f in content if f.endswith('.py')]
    assert len(pyfiles) >= 5, \
        'There are less than 3 submodules (additional .py files in module)'
    assert 'templates' in content, \
        'No templates (for web app) in the module'
