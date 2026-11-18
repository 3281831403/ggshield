from typing import Any, List

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.config.user_config import add_ignored_matches_to_config_file
from ggshield.core.text_utils import pluralize
from ggshield.core.types import IgnoredMatch


@click.command()
@click.argument(
    "secret_sha",
    nargs=1,
    type=str,
    required=False,
    metavar="SECRET_SHA",
)
@click.option(
    "--last-found",
    is_flag=True,
    help="Ignore secrets found in the last `ggshield secret scan` run.",
)
@click.option(
    "--name",
    type=str,
    help="Name of the secret to ignore.",
    metavar="NAME",
)
@add_common_options()
@click.pass_context
def ignore_cmd(
    ctx: click.Context,
    secret_sha: str,
    name: str,
    last_found: bool,
    **kwargs: Any,
) -> None:
    """
    Ignore some secrets.

    The `secret ignore` command instructs ggshield to ignore secrets.

    Option `--name` allows to specify the name of the secret to ignore.

    Option `--last-found` ignores all secrets found during the last scan.

    The command adds the ignored secrets to the `secrets.ignored_matches` section of your local
    configuration file. If no local configuration file is found, a `.gitguardian.yaml` file is created.
    """

    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    path = config.config_path

    if last_found:
        if secret_sha or name:
            raise click.UsageError(
                "Option `--last-found` cannot be used with `SECRET_SHA` or `--name`."
            )
        ignored_matches: List[IgnoredMatch] = list(ctx_obj.cache.last_found_secrets)
    else:
        if not name:
            raise click.UsageError(
                "Option `--name` is required when ignoring a secret."
            )
        ignored_matches = [IgnoredMatch(name=name, match=secret_sha)]

    # Shas already ignored through any configuration file (e.g. the global
    # one): they must not be copied into the local configuration file.
    known_match_shas = {
        match.match for match in config.user_config.secret.ignored_matches
    }

    # Update the in-memory (merged) configuration
    for ignored_match in ignored_matches:
        config.add_ignored_match(ignored_match)

    # Only append the new ignored matches to the local configuration file,
    # without dumping settings coming from other configuration files into it
    add_ignored_matches_to_config_file(path, ignored_matches, known_match_shas)

    nb = len(ignored_matches)
    secrets_word = pluralize("secret", nb)
    click.echo(
        f"Added {nb} {secrets_word} to the secret.ignored_matches section of {path}."
    )


def ignore_last_found(config: Config, cache: Cache) -> int:
    """
    Add last found secrets from .cache_ggshield into ignored_matches
    in the local .gitguardian.yaml config file so that they are ignored on next run
    Secrets are added as `hash`
    """
    for secret in cache.last_found_secrets:
        config.add_ignored_match(secret)
    return len(cache.last_found_secrets)
