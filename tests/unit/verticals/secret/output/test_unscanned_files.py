"""
Contract tests for reporting content the API did not scan in the three output
formats (text, JSON, SARIF). An unscanned file must show up in every format,
exactly once per failure, and must never make a scan look clean.
"""

import json

from ggshield.core.config.user_config import SecretConfig
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret import Error, Results, SecretScanCollection
from ggshield.verticals.secret.output import (
    SecretJSONOutputHandler,
    SecretSARIFOutputHandler,
    SecretTextOutputHandler,
)


FAILURE = "Some files were not scanned: GitGuardian did not scan the content (HTTP 429: Nope)."


def _unscanned_commit(
    sha: str, files: list[tuple[str, Filemode]]
) -> SecretScanCollection:
    return SecretScanCollection(
        id=sha,
        type="commit",
        results=Results(
            results=[],
            errors=[Error(files=list(files), description=FAILURE)],
        ),
        optional_header=f"\ncommit {sha}\nAuthor: a <a@x>\nDate: d\n",
    )


def _range(secret_config: SecretConfig) -> SecretScanCollection:
    clean = SecretScanCollection(
        id="c1",
        type="commit",
        results=Results(),
        optional_header="\ncommit c1\nAuthor: a <a@x>\nDate: d\n",
    )
    unscanned = _unscanned_commit("c2", [("commit://c2/leak.conf", Filemode.NEW)])
    return SecretScanCollection(
        id="range", type="commit-range", scans=[clean, unscanned]
    )


def test_text_output_lists_unscanned_files_and_keeps_quiet_about_cleanliness():
    handler = SecretTextOutputHandler(verbose=False, secret_config=SecretConfig())

    text = handler._process_scan_impl(_range(SecretConfig()))

    assert FAILURE in text
    assert "commit://c2/leak.conf" in text
    assert "commit c2" in text
    # A partial scan must not claim everything is clean
    assert "No secrets have been found" not in text


def test_json_output_lists_every_commit_with_its_error_once():
    handler = SecretJSONOutputHandler(verbose=False, secret_config=SecretConfig())

    payload = json.loads(handler._process_scan_impl(_range(SecretConfig())))

    assert [scan["id"] for scan in payload["scans"]] == ["c1", "c2"]
    unscanned_scan = payload["scans"][1]
    assert unscanned_scan["errors"] == [
        {
            "files": [
                {"filename": "commit://c2/leak.conf", "mode": "NEW"},
            ],
            "description": FAILURE,
        }
    ]
    # The same failure is not duplicated on the clean commit
    assert "errors" not in payload["scans"][0]


def test_json_output_dedupes_one_failure_affecting_several_files():
    error = Error(
        files=[
            ("commit://c2/a", Filemode.NEW),
            ("commit://c2/b", Filemode.MODIFY),
        ],
        description=FAILURE,
    )
    collection = SecretScanCollection(
        id="c2",
        type="commit",
        results=Results(errors=[error, error]),
    )
    # The repo layer dedupes before rendering
    collection.results.errors = [error]

    handler = SecretJSONOutputHandler(verbose=False, secret_config=SecretConfig())
    payload = json.loads(handler._process_scan_impl(collection))

    assert len(payload["errors"]) == 1
    assert {f["filename"] for f in payload["errors"][0]["files"]} == {
        "commit://c2/a",
        "commit://c2/b",
    }


def test_sarif_output_emits_notifications_for_unscanned_files():
    handler = SecretSARIFOutputHandler(verbose=False, secret_config=SecretConfig())

    payload = json.loads(handler._process_scan_impl(_range(SecretConfig())))

    run = payload["runs"][0]
    notifications = run["toolExecutionNotifications"]
    assert len(notifications) == 1
    notification = notifications[0]
    assert notification["level"] == "error"
    assert notification["message"]["text"] == FAILURE
    assert notification["locations"] == [
        {"physicalLocation": {"artifactLocation": {"uri": "commit://c2/leak.conf"}}}
    ]


def test_sarif_output_without_unscanned_files_has_no_notifications():
    handler = SecretSARIFOutputHandler(verbose=False, secret_config=SecretConfig())
    collection = SecretScanCollection(id="ok", type="commit", results=Results())

    payload = json.loads(handler._process_scan_impl(collection))

    assert "toolExecutionNotifications" not in payload["runs"][0]


def test_exit_code_non_zero_with_unscanned_content_by_default():
    from ggshield.core.errors import ExitCode

    handler = SecretJSONOutputHandler(verbose=False, secret_config=SecretConfig())
    assert handler._get_exit_code(_range(SecretConfig())) == (
        ExitCode.SCAN_FOUND_PROBLEMS
    )


def test_exit_code_zero_in_fail_open_mode_when_no_secret_found():
    from ggshield.core.errors import ExitCode

    handler = SecretJSONOutputHandler(
        verbose=False,
        secret_config=SecretConfig(fail_on_server_error=False),
    )
    assert handler._get_exit_code(_range(SecretConfig())) == ExitCode.SUCCESS
