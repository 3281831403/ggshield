from __future__ import annotations

import concurrent.futures
import json
import logging
import os
from ast import literal_eval
from concurrent.futures import Future
from typing import Dict, Iterable, List, Optional, Tuple, Union

import click
import requests
from pygitguardian import GGClient
from pygitguardian.models import Detail, MultiScanResult, TokenScope

from ggshield.core import ui
from ggshield.core.cache import Cache
from ggshield.core.client import check_client_api_key
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.constants import MAX_WORKERS
from ggshield.core.errors import (
    ServiceUnavailableError,
    UnexpectedError,
    describe_http_error,
    handle_api_error,
)
from ggshield.core.scan import DecodeError, ScanContext, Scannable
from ggshield.core.scan.scannable import NonSeekableFileError
from ggshield.core.scanner_ui.scanner_ui import ScannerUI
from ggshield.core.text_utils import pluralize
from ggshield.utils.git_shell import Filemode

from .secret_scan_collection import Error, Result, Results


# GitGuardian API does not accept paths longer than this
_API_PATH_MAX_LENGTH = 256
# Room for the request envelope around the documents (brackets, source_uuid)
_SIZE_METADATA_OVERHEAD = 10240  # 10 KB


logger = logging.getLogger(__name__)


ScanFuture = Future[Union[Detail, MultiScanResult]]


class SecretScanner:
    """
    A SecretScanner scans a list of Scannable, using multiple threads
    """

    def __init__(
        self,
        client: GGClient,
        cache: Cache,
        scan_context: ScanContext,
        secret_config: SecretConfig,
        check_api_key: Optional[bool] = True,
    ):
        if check_api_key:
            scopes = get_required_token_scopes_from_config(secret_config)
            check_client_api_key(client, scopes)

        self.client = client
        self.cache = cache
        self.secret_config = secret_config
        self.headers = scan_context.get_http_headers()
        self.headers.update({"scan_options": secret_config.dump_for_monitoring()})

        self.command_id = scan_context.command_id

    def scan(
        self,
        files: Iterable[Scannable],
        scanner_ui: ScannerUI,
        scan_threads: Optional[int] = None,
        raise_on_failure: bool = True,
    ) -> Results:
        """
        Starts the scan, using at most `scan_threads`. If `scan_threads` is not set,
        defaults to MAX_WORKERS.
        Reports progress through `scanner_ui`.
        Returns a Results instance.

        By default a chunk the API did not scan raises, so the command fails
        fast instead of reporting unscanned content as clean. Historical scans
        pass `raise_on_failure=False`: every failure is then returned as an
        Error naming the unscanned files, and the caller accounts for them.
        """
        if scan_threads is None:
            scan_threads = MAX_WORKERS
        logger.debug("command_id=%s scan_threads=%d", self.command_id, scan_threads)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=scan_threads, thread_name_prefix="content_scan"
        ) as executor:
            chunks_for_futures = self._start_scans(
                executor,
                files,
                scanner_ui,
            )

            return self._collect_results(
                scanner_ui, chunks_for_futures, raise_on_failure
            )

    def _document_filename(self, scannable: Scannable) -> str:
        """
        Compute the filename sent to the API for `scannable`, truncated to the maximum
        length the API accepts. When `filename_only` is set, only the basename is sent
        so incidents don't record the full path.
        """
        filename = scannable.filename
        if self.secret_config.filename_only:
            filename = os.path.basename(filename) or filename
        return filename[-_API_PATH_MAX_LENGTH:]

    def _document(self, scannable: Scannable) -> Dict[str, str]:
        return {
            "document": scannable.content,
            "filename": self._document_filename(scannable),
        }

    def _document_payload_size(self, scannable: Scannable) -> int:
        # The API caps the JSON body, which requests escapes with ensure_ascii (up to 6x)
        separator_size = 2  # ", " between list items
        return len(json.dumps(self._document(scannable))) + separator_size

    def _scan_chunk(
        self, executor: concurrent.futures.ThreadPoolExecutor, chunk: List[Scannable]
    ) -> ScanFuture:
        """
        Sends a chunk of files to scan to the API
        """
        documents = [self._document(x) for x in chunk]

        # Use scan_and_create_incidents if source_uuid is provided, otherwise use multi_content_scan
        if self.secret_config.source_uuid:
            return executor.submit(
                self.client.scan_and_create_incidents,
                documents,
                self.secret_config.source_uuid,
                extra_headers=self.headers,
            )
        else:
            return executor.submit(
                self.client.multi_content_scan,
                documents,
                self.headers,
                all_secrets=True,
            )

    def _start_scans(
        self,
        executor: concurrent.futures.ThreadPoolExecutor,
        scannables: Iterable[Scannable],
        scanner_ui: ScannerUI,
    ) -> Dict[ScanFuture, List[Scannable]]:
        """
        Start all scans, return a tuple containing:
        - a mapping of future to the list of files it is scanning
        - a list of files which we did not send to scan because we could not decode them
        """
        chunks_for_futures = {}

        chunk: List[Scannable] = []
        max_payload_size = self.client.maximum_payload_size - _SIZE_METADATA_OVERHEAD
        chunk_payload_size = 0
        maximum_document_size = int(
            os.getenv(
                "GG_MAX_DOC_SIZE",
                self.client.secret_scan_preferences.maximum_document_size,
            )
        )
        maximum_documents_per_scan = int(
            os.getenv(
                "GG_MAX_DOCS",
                self.client.secret_scan_preferences.maximum_documents_per_scan,
            )
        )
        logging.debug("max_doc_size=%d", maximum_document_size)
        logging.debug("max_docs=%d", maximum_documents_per_scan)
        for scannable in scannables:
            try:
                if scannable.is_longer_than(maximum_document_size):
                    scanner_ui.on_skipped(
                        scannable, f"content is over {maximum_document_size:,} bytes"
                    )
                    continue
                content = scannable.content
            except DecodeError:
                scanner_ui.on_skipped(scannable, "can't detect encoding")
                continue
            except NonSeekableFileError:
                scanner_ui.on_skipped(scannable, "file cannot be seeked")
                continue
            except FileNotFoundError:
                scanner_ui.on_skipped(scannable, "file not found")
                continue

            if not content:
                scanner_ui.on_skipped(scannable, "")
                continue

            document_payload_size = self._document_payload_size(scannable)
            if document_payload_size > max_payload_size:
                scanner_ui.on_skipped(
                    scannable,
                    f"encoded content is over the {max_payload_size:,} bytes"
                    " payload limit",
                )
                continue

            if chunk and (
                len(chunk) == maximum_documents_per_scan
                or chunk_payload_size + document_payload_size > max_payload_size
            ):
                future = self._scan_chunk(executor, chunk)
                chunks_for_futures[future] = chunk
                chunk = []
                chunk_payload_size = 0
            chunk.append(scannable)
            chunk_payload_size += document_payload_size
        if chunk:
            future = self._scan_chunk(executor, chunk)
            chunks_for_futures[future] = chunk
        return chunks_for_futures

    def _collect_results(
        self,
        scanner_ui: ScannerUI,
        chunks_for_futures: Dict[ScanFuture, List[Scannable]],
        raise_on_failure: bool,
    ) -> Results:
        """
        Receive scans as they complete, report progress and collect them and return
        a Results.
        """
        self.cache.purge()

        results = []
        errors: List[Error] = []
        failures: List[click.ClickException] = []
        for future in concurrent.futures.as_completed(chunks_for_futures):
            chunk = chunks_for_futures[future]
            scanner_ui.on_scanned(chunk)

            try:
                scan, scan_error = _get_chunk_scan(future, chunk)
            except click.ClickException as exc:
                if raise_on_failure or not isinstance(exc, ServiceUnavailableError):
                    # In fail-fast mode any failure aborts. In collect mode
                    # (--no-fail-on-server-error) only a skippable server
                    # failure becomes a report error: anything else, e.g. a
                    # quota limit, must still abort the command.
                    failures.append(exc)
                    continue
                errors.append(_chunk_scan_error(exc, chunk))
                continue
            if scan_error is not None:
                # A 400 faults the chunk's files without raising: record them so
                # they are reported as unscanned instead of vanishing
                errors.append(scan_error)
            if scan is None:
                continue

            for file, scan_result in zip(chunk, scan.scan_results):
                result = Result.from_scan_result(file, scan_result, self.secret_config)
                for secret in result.secrets:
                    self.cache.add_found_policy_break(
                        secret.detector_display_name,
                        secret.get_ignore_sha(),
                        file.filename,
                    )
                results.append(result)

        if failures:
            # Prefer a failure --no-fail-on-server-error cannot skip, so a quota
            # error running next to a throttled chunk always wins
            raise next(
                (
                    failure
                    for failure in failures
                    if not isinstance(failure, ServiceUnavailableError)
                ),
                failures[0],
            )

        self.cache.save()
        return Results(results=results, errors=errors)


def _chunk_scan_error(exc: click.ClickException, chunk: List[Scannable]) -> Error:
    """
    Build the Error describing a chunk the API did not scan, naming every file
    of the chunk so reports can list them as unscanned.
    """
    return Error(
        files=[(file.filename, file.filemode) for file in chunk],
        description=f"Some files were not scanned: {exc.format_message()}",
    )


def report_scan_failures(errors: List[Error]) -> List[Error]:
    """
    Merge the errors collected while scanning: a given failure message is
    reported only once, but the files of every chunk it hit are kept together.
    Errors stay ordered by their first occurrence.
    """
    merged: Dict[str, Error] = {}
    order: List[str] = []
    for error in errors:
        existing = merged.get(error.description)
        if existing is None:
            merged[error.description] = Error(
                files=list(error.files), description=error.description
            )
            order.append(error.description)
        else:
            known = {file for file in existing.files}
            existing.files.extend(file for file in error.files if file not in known)
    return [merged[description] for description in order]


def _get_chunk_scan(
    future: ScanFuture, chunk: List[Scannable]
) -> Tuple[Optional[MultiScanResult], Optional[Error]]:
    """
    Return the scan of `chunk` and, when the API rejected some of its files with
    a 400, the Error listing the unscanned files. Raise when the API did not scan
    the chunk at all.
    """
    exception = future.exception()
    if exception is not None:
        # Only failing to get an answer (unreachable, SSL, timeout, retries
        # exhausted on a 5xx) is eligible for the --no-fail-on-server-error skip
        # path. Any other exception is opaque (JSON decode, internal bug, ...)
        # and must not be silently swallowed when fail-open is enabled.
        if isinstance(
            exception,
            (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RetryError,
            ),
        ):
            raise ServiceUnavailableError(
                f"Scanning failed: {exception}"
            ) from exception
        raise UnexpectedError(f"Scanning failed: {exception}") from exception

    scan = future.result()
    # Not `scan.success`: a proxy page with status 200 is a Detail too
    if isinstance(scan, Detail):
        if scan.status_code == 200 and scan.detail.lstrip().startswith(("[", "{")):
            # py-gitguardian only reads a result sent as exactly "application/json":
            # this one may hold a secret, so --no-fail-on-server-error must not skip it
            raise UnexpectedError("Could not read the scan result sent by GitGuardian.")
        if scan.status_code == 400:
            handle_scan_chunk_error(scan, chunk)
            return None, Error(
                files=_faulty_400_files(scan, chunk),
                description=(
                    "Some files were not scanned: the API rejected the request"
                    f" ({describe_http_error(scan)})."
                ),
            )
        handle_scan_chunk_error(scan, chunk)
        return None, None
    assert isinstance(scan, MultiScanResult)
    return scan, None


def _faulty_400_files(
    detail: Detail, chunk: List[Scannable]
) -> List[Tuple[str, Filemode]]:
    """
    Extract the files a 400 response rejects one by one from its per-file detail
    list. Empty entries mean the API accepted the file at that index. When the
    body is not a per-file list, every file of the chunk is affected.
    """
    try:
        details = literal_eval(detail.detail)
    except Exception:
        details = None

    if isinstance(details, list) and len(details) == len(chunk):
        return [
            (file.filename, file.filemode)
            for file, inner_detail in zip(chunk, details)
            if inner_detail
        ]
    return [(file.filename, file.filemode) for file in chunk]


def handle_scan_chunk_error(detail: Detail, chunk: List[Scannable]) -> None:
    handle_api_error(detail)
    details = None

    if "Source" in detail.detail and "not found" in detail.detail:
        raise UnexpectedError("The provided source was not found in GitGuardian.")

    status = describe_http_error(detail)

    # Only a 400 faults the files we sent. Any other status means the API scanned
    # nothing, and dropping the chunk would report it as clean.
    if detail.status_code != 400:
        message = f"GitGuardian did not scan the content ({status})."
        if detail.status_code == 403:
            # A firewall usually blocks with a 403, and its plain-text answer
            # looks just like one from GitGuardian
            message += (
                " If this machine is behind a proxy, a firewall or an IP allowlist,"
                " check that it can reach GitGuardian."
            )
        if detail.status_code == 413:
            # Retrying never helps: name the files so they can be excluded
            filenames = "\n".join(f"- {file.filename}" for file in chunk)
            message += f" The request was too large for:\n{filenames}"
        raise ServiceUnavailableError(message)

    ui.display_error("Scanning failed. Results may be incomplete.")
    try:
        # try to load as list of dicts to get per file details
        details = literal_eval(detail.detail)
    except Exception:
        pass

    if isinstance(details, list) and details:
        # if the details had per file details
        ui.display_error(
            f"Add the following {pluralize('file', len(details))}"
            " to your ignored_paths:"
        )
        for i, inner_detail in enumerate(details):
            if inner_detail:
                ui.display_error(f"- {chunk[i].filename}: {str(inner_detail)}")
    else:
        # if the details had a request error
        filenames = "\n".join(f"- {file.filename}" for file in chunk)
        ui.display_error(f"The following chunk is affected:\n{filenames}")
        ui.display_error(str(detail))


def get_required_token_scopes_from_config(
    secret_config: SecretConfig,
) -> set[TokenScope]:
    """
    Get the required token scopes based on the secret configuration.

    Args:
        secret_config: The secret configuration to analyze

    Returns:
        A set of TokenScope values required for the given configuration
    """
    scopes = {TokenScope.SCAN}
    if secret_config.with_incident_details:
        scopes.add(TokenScope.INCIDENTS_READ)
    if secret_config.source_uuid:
        scopes.add(TokenScope.SCAN_CREATE_INCIDENTS)
    return scopes
