import itertools
import logging
import traceback
from collections.abc import Iterable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from re import Pattern
from typing import Callable, List, Set, Tuple

from click import ClickException, UsageError
from pygitguardian import GGClient

from ggshield.core import ui
from ggshield.core.cache import Cache
from ggshield.core.client import check_client_api_key
from ggshield.core.config import Config
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.constants import MAX_WORKERS
from ggshield.core.errors import (
    ExitCode,
    ServiceUnavailableError,
    UnexpectedError,
    handle_exception,
)
from ggshield.core.scan import Commit, ScanContext
from ggshield.core.scan.commit_utils import CommitScannable
from ggshield.core.scanner_ui import create_message_only_scanner_ui
from ggshield.core.text_utils import STYLE, format_text
from ggshield.utils.git_shell import Filemode, get_list_commit_SHA, is_git_dir
from ggshield.utils.os import cd
from ggshield.verticals.secret.secret_scanner import (
    get_required_token_scopes_from_config,
    report_scan_failures,
)

from .output import SecretOutputHandler
from .secret_scan_collection import Error, Results, SecretScanCollection
from .secret_scanner import SecretScanner


logger = logging.getLogger(__name__)


# We add a maximal value to avoid silently consuming all threads on powerful machines
SCAN_THREADS = 4


def scan_repo_path(
    client: GGClient,
    cache: Cache,
    output_handler: SecretOutputHandler,
    exclusion_regexes: Set[Pattern[str]],
    config: Config,
    scan_context: ScanContext,
    repo_path: Path,
) -> int:  # pragma: no cover
    try:
        if not is_git_dir(repo_path):
            raise UsageError(f"{repo_path} is not a git repository")

        with cd(repo_path):
            return scan_commit_range(
                client=client,
                cache=cache,
                commit_list=get_list_commit_SHA("--all"),
                output_handler=output_handler,
                exclusion_regexes=exclusion_regexes,
                scan_context=scan_context,
                secret_config=config.user_config.secret,
            )
    except Exception as error:
        return handle_exception(error)


def _commit_scan_error(commit: Commit, description: str) -> Error:
    """
    Build an Error listing every file of `commit` as unscanned. Used for batches
    the API did not answer or that never ran, so the commit still appears in the
    report instead of silently dropping out of it.
    """
    files = [
        (CommitScannable.create_url(commit.sha, path), Filemode.UNKNOWN)
        for path in commit.info.paths
    ]
    return Error(files=files, description=description)


def _commit_collection(
    commit: Commit,
    results_for_commit_files: list,
    errors: List[Error],
) -> SecretScanCollection:
    optional_header = (
        format_text(f"\ncommit {commit.sha}\n", STYLE["commit_info"])
        + f"Author: {commit.info.author} <{commit.info.email}>\n"
        + f"Date: {commit.info.date}\n"
    )

    return SecretScanCollection(
        commit.sha or "unknown",
        type="commit",
        results=Results(
            results=results_for_commit_files,
            errors=errors,
        ),
        optional_header=optional_header,
        extra_info={
            "author": commit.info.author,
            "email": commit.info.email,
            "date": commit.info.date,
        },
    )


def scan_commits_content(
    commits: List[Commit],
    client: GGClient,
    cache: Cache,
    scan_context: ScanContext,
    secret_config: SecretConfig,
    progress_callback: Callable[[int], None],
    commit_scanned_callback: Callable[[Commit], None],
    raise_on_failure: bool = True,
) -> SecretScanCollection:  # pragma: no cover
    try:
        commit_files = itertools.chain.from_iterable(c.get_files() for c in commits)

        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=scan_context,
            check_api_key=False,  # Key has been checked in `scan_commit_range()`
            secret_config=secret_config,
        )
        with create_message_only_scanner_ui() as scanner_ui:
            # In fail-open mode failures are collected so every commit of the
            # batch ends up either scanned or listed as unscanned
            results = scanner.scan(
                commit_files,
                scan_threads=SCAN_THREADS,
                scanner_ui=scanner_ui,
                raise_on_failure=raise_on_failure,
            )
    except ClickException:
        # scan_commit_range decides whether a failed batch fails the command
        raise
    except Exception as exc:
        logger.error(
            "Exception raised during scan. commits=%s type(exception)=%s exception=%s trace=%s",
            commits,
            type(exc),
            exc,
            traceback.format_exc(),
        )
        raise UnexpectedError(f"Scanning failed: {exc}") from exc
    finally:
        progress_callback(len(commits))
        for commit in commits:
            commit_scanned_callback(commit)

    result_for_urls = {result.url: result for result in results.results}
    # Map each error back to the commits whose files it lists, so a single chunk
    # failure is reported once instead of being duplicated on every commit
    urls_to_commits = {url: commit for commit in commits for url in commit.urls}
    errors_by_commit = {id(commit): [] for commit in commits}
    for error in results.errors:
        affected = {urls_to_commits[filename] for filename, _ in error.files}
        for commit in affected:
            errors_by_commit[id(commit)].append(error)

    scans = []
    for commit in commits:
        results_for_commit_files = [
            result_for_urls[u] for u in commit.urls if u in result_for_urls
        ]
        scans.append(
            _commit_collection(
                commit,
                results_for_commit_files,
                errors_by_commit[id(commit)],
            )
        )

    return SecretScanCollection(
        id=scan_context.command_id, type="commit-ranges", scans=scans
    )


def get_commits_by_batch(
    commits: Iterable[Commit],
    batch_max_size: int,
) -> Iterator[List[Commit]]:
    """
    Given a list of commit shas yield the commit files
    by biggest batches possible of length at most `batch_max_size`
    """
    current_count = 0
    batch = []
    for commit in commits:
        num_files = len(commit.urls)
        if current_count + num_files < batch_max_size:
            batch.append(commit)
            current_count += num_files
        else:
            # The first batch can remain empty if it has too many files
            if batch:
                yield batch
            current_count = num_files
            batch = [commit]
    # Send the last batch that remains
    yield batch


def scan_commit_range(
    client: GGClient,
    cache: Cache,
    commit_list: List[str],
    output_handler: SecretOutputHandler,
    exclusion_regexes: Set[Pattern[str]],
    scan_context: ScanContext,
    secret_config: SecretConfig,
    include_staged: bool = False,
) -> ExitCode:
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_list: List of commits sha to scan
    :param verbose: Display successful scan's message
    """
    check_client_api_key(client, get_required_token_scopes_from_config(secret_config))
    max_documents = client.secret_scan_preferences.maximum_documents_per_scan

    with ui.create_progress(len(commit_list) + int(include_staged)) as progress:
        commits_iters: list[Iterable[Commit]] = []
        if include_staged:
            commits_iters.append(
                (Commit.from_staged(exclusion_regexes=exclusion_regexes),)
            )
        commits_iters.append(
            Commit.from_sha(sha, exclusion_regexes=exclusion_regexes)
            for sha in commit_list
        )
        commits_batch = get_commits_by_batch(
            commits=itertools.chain(*commits_iters),
            batch_max_size=max_documents,
        )

        def commit_scanned_callback(commit: Commit):
            if include_staged and commit.sha is None:
                ui.display_verbose("Scanned staged changes")
            else:
                ui.display_verbose(f"Scanned {commit.sha}")

        # Remember the commits of every batch: when a batch fails or is
        # cancelled, they still have to be listed as unscanned in the report
        future_commits: List[Tuple[Future, List[Commit]]] = []
        # --no-fail-on-server-error switches scanning to collect mode: chunk
        # failures become report errors instead of aborting the batch
        raise_on_failure = secret_config.fail_on_server_error
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for commits in commits_batch:
                future = executor.submit(
                    scan_commits_content,
                    commits,
                    client,
                    cache,
                    scan_context,
                    secret_config,
                    progress.advance,
                    commit_scanned_callback,
                    raise_on_failure,
                )
                future_commits.append((future, commits))

            scans: List[SecretScanCollection] = []
            batch_failures: List[ClickException] = []
            try:
                # in submission order so we preserve the order
                for future, commits in future_commits:
                    if future.cancelled():
                        # The batch never ran because another one failed
                        cancellation = ServiceUnavailableError(
                            "Scanning failed: the batch was cancelled after"
                            " another batch failed."
                        )
                        if _fail_open_allows(secret_config, cancellation):
                            scans.extend(
                                _unscanned_batch_collections(commits, cancellation)
                            )
                            continue
                        batch_failures.append(cancellation)
                        continue
                    try:
                        scan_collection = future.result()
                    except ClickException as exc:
                        # In fail-open mode, skippable failures keep every
                        # commit in the report, listed as unscanned, and exit 0.
                        # Other failures stop the remaining batches: the one
                        # that cannot be skipped must win, whatever the
                        # completion order.
                        if _fail_open_allows(secret_config, exc):
                            executor.shutdown(cancel_futures=True)
                            scans.extend(_unscanned_batch_collections(commits, exc))
                            continue
                        executor.shutdown(cancel_futures=True)
                        batch_failures.append(exc)
                        continue
                    scans.extend(scan_collection.scans)
            except Exception:
                # Don't run the remaining batches if one already failed
                executor.shutdown(cancel_futures=True)
                raise

            if batch_failures:
                raise next(
                    (
                        failure
                        for failure in batch_failures
                        if not isinstance(failure, ServiceUnavailableError)
                    ),
                    batch_failures[0],
                )

    collection = SecretScanCollection(
        id=scan_context.command_id, type="commit-range", scans=scans
    )
    _dedupe_collection_errors(collection)
    return output_handler.process_scan(collection)


def _fail_open_allows(secret_config: SecretConfig, exc: ClickException) -> bool:
    """
    Whether `--no-fail-on-server-error` lets this failure through. Only a
    skippable server unavailability can be skipped; every other failure still
    aborts the command.
    """
    return (
        isinstance(exc, ServiceUnavailableError)
        and not secret_config.fail_on_server_error
    )


def _dedupe_collection_errors(collection: SecretScanCollection) -> None:
    """
    The same chunk failure is mapped onto each commit whose files it contains:
    collapse it to a single Error per commit and drop errors that no longer name
    any file of that commit.
    """
    for scan in collection.scans or []:
        if scan.results is None:
            continue
        scan.results.errors = report_scan_failures(scan.results.errors)


def _unscanned_batch_collections(
    commits: List[Commit], failure: ClickException
) -> List[SecretScanCollection]:
    """
    Build commit collections for batches the API did not answer: every commit of
    the batch is reported, with all its files listed as unscanned, instead of
    disappearing from the report.
    """
    description = f"Some files were not scanned: {failure.format_message()}"
    return [
        _commit_collection(
            commit,
            results_for_commit_files=[],
            errors=[_commit_scan_error(commit, description)],
        )
        for commit in commits
    ]
