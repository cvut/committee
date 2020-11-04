import pathlib

from committee.logic import RuleMessage, RulePath, RuleStats


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





