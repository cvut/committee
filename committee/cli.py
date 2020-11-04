import click
import configparser

from committee.config import ConfigLoader
from committee.logic import Committee, CommitteeResult, GitHubClient


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
def main(reposlug, config, author, path, ref, force, output_format, dry_run):
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
