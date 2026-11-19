import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, TypedDict
from unittest import mock

import pytest
from pygitguardian import GGClient
from pygitguardian.models import ScanResult, SecretIncident
from pytest_voluptuous import S
from voluptuous import Optional as VOptional
from voluptuous import validators

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.lines import Line, get_lines_from_content
from ggshield.core.match_span import MatchSpan
from ggshield.core.scan import Commit
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret import Result, Results, SecretScanCollection
from ggshield.verticals.secret.extended_match import ExtendedMatch
from ggshield.verticals.secret.output import (
    SecretJSONOutputHandler,
    SecretSARIFOutputHandler,
)
from ggshield.verticals.secret.output.secret_sarif_output_handler import (
    IGNORE_SHA_FINGERPRINT_KEY,
    SCHEMA_URL,
    UNIQUE_FINGERPRINT_KEY,
)
from ggshield.verticals.secret.secret_scan_collection import Result as SecretResult
from ggshield.verticals.secret.secret_scan_collection import Secret
from tests.factories import PolicyBreakFactory, ScannableFactory, ScanResultFactory
from tests.unit.conftest import (
    _MULTI_SECRET_ONE_LINE_FULL_PATCH,
    _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
    _MULTIPLE_SECRETS_PATCH,
    _MULTIPLE_SECRETS_SCAN_RESULT,
    _ONE_LINE_AND_MULTILINE_PATCH,
    _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
    SECRET_INCIDENT_MOCK,
)


VERSION_VALIDATOR = validators.Match(r"\d+\.\d+\.\d+")

SARIF_RULE_SCHEMA = S(
    {
        "id": str,
        VOptional("helpUri"): str,
    }
)

TOOL_SCHEMA = S(
    {
        "driver": {
            "organization": "GitGuardian",
            "name": "ggshield",
            "informationUri": str,
            "version": VERSION_VALIDATOR,
            "rules": [SARIF_RULE_SCHEMA],
        },
        "extensions": [
            {
                "name": str,
                "version": VERSION_VALIDATOR,
            }
        ],
    }
)

EMPTY_RESULT_SCHEMA = S(
    {
        "version": "2.1.0",
        "$schema": SCHEMA_URL,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "organization": "GitGuardian",
                        "name": "ggshield",
                        "informationUri": str,
                        "version": VERSION_VALIDATOR,
                        "rules": [],
                    },
                    "extensions": [
                        {
                            "name": str,
                            "version": VERSION_VALIDATOR,
                        }
                    ],
                },
                "results": [],
            }
        ],
    }
)

MIN_1_INT = validators.Range(min=1)

SARIF_PHYSICAL_LOCATION_DICT_SCHEMA = S(
    {
        "artifactLocation": {
            "uri": str,
        },
        "region": {
            "startLine": MIN_1_INT,
            "startColumn": MIN_1_INT,
            "endLine": MIN_1_INT,
            "endColumn": MIN_1_INT,
        },
    }
)

SARIF_RESULT_DICT_SCHEMA = S(
    {
        "ruleId": str,
        "ruleIndex": int,
        "level": "error",
        "message": {
            "text": str,
            "markdown": str,
        },
        "locations": [
            {
                "physicalLocation": SARIF_PHYSICAL_LOCATION_DICT_SCHEMA,
            }
        ],
        "relatedLocations": [
            {
                "id": int,
                "physicalLocation": SARIF_PHYSICAL_LOCATION_DICT_SCHEMA,
                "message": {"text": str},
            }
        ],
        "partialFingerprints": {
            IGNORE_SHA_FINGERPRINT_KEY: str,
            UNIQUE_FINGERPRINT_KEY: str,
        },
        VOptional("hostedViewerUri"): str,
        VOptional("properties"): {
            VOptional("incidentDetails"): dict,
        },
    }
)

SCHEMA_WITH_INCIDENTS = S(
    {
        "version": "2.1.0",
        "$schema": SCHEMA_URL,
        "runs": [{"tool": TOOL_SCHEMA, "results": [SARIF_RESULT_DICT_SCHEMA]}],
    }
)


@pytest.fixture()
def init_secrets_engine_version():
    # Init secrets engine version: it's not set if we don't make an API call
    with mock.patch(
        "ggshield.verticals.secret.output.secret_sarif_output_handler.VERSIONS"
    ) as versions:
        versions.secrets_engine_version = "3.14.1"
        yield


def test_sarif_output_no_secrets(init_secrets_engine_version):
    """
    GIVEN an empty scan collection
    WHEN SecretSARIFOutputHandler runs on it
    THEN it outputs an empty SARIF document
    """
    scan = SecretScanCollection(id="path", type="test", results=Results())
    handler = SecretSARIFOutputHandler(
        verbose=True, secret_config=SecretConfig(show_secrets=False)
    )
    output = handler._process_scan_impl(scan)
    dct = json.loads(output)

    assert EMPTY_RESULT_SCHEMA == dct


@pytest.mark.parametrize(
    "patch,scan_result",
    [
        pytest.param(
            _MULTIPLE_SECRETS_PATCH,
            _MULTIPLE_SECRETS_SCAN_RESULT,
            id="_MULTIPLE_SECRETS_PATCH",
        ),
        pytest.param(
            _MULTI_SECRET_ONE_LINE_FULL_PATCH,
            _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
            id="_MULTI_SECRET_ONE_LINE_FULL_PATCH",
        ),
        pytest.param(
            _ONE_LINE_AND_MULTILINE_PATCH,
            _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
            id="_ONE_LINE_AND_MULTILINE_PATCH",
        ),
    ],
)
@pytest.mark.parametrize("with_incident_details", [True, False])
@pytest.mark.parametrize("known_incidents", [True, False])
def test_sarif_output_for_flat_scan_with_secrets(
    init_secrets_engine_version,
    patch: str,
    scan_result: ScanResult,
    with_incident_details: bool,
    known_incidents: bool,
):
    """
    GIVEN a patch containing secrets and a scan result
    WHEN SecretSARIFOutputHandler runs on it
    THEN it outputs a SARIF document pointing to the secrets
    """
    scan_result = deepcopy(scan_result)
    client_mock = mock.Mock(spec=GGClient)
    client_mock.retrieve_secret_incident.return_value = SECRET_INCIDENT_MOCK

    secret_config = SecretConfig(
        show_secrets=False,
        with_incident_details=with_incident_details,
    )
    handler = SecretSARIFOutputHandler(
        verbose=True, secret_config=secret_config, client=client_mock
    )

    commit = Commit.from_patch(patch)
    scannable = next(commit.get_files())

    for index, policy_break in enumerate(scan_result.policy_breaks):
        if known_incidents:
            policy_break.known_secret = True
            policy_break.incident_url = (
                f"https://dashboard.gitguardian.com/workspace/1/incidents/{index}"
            )
        else:
            policy_break.known_secret = False
            policy_break.incident_url = None

    result = Result.from_scan_result(
        file=scannable, scan_result=scan_result, secret_config=SecretConfig()
    )
    results = Results(results=[result])
    scan = SecretScanCollection(id="path", type="test", results=results)

    output = handler._process_scan_impl(scan)
    json_dict = json.loads(output)

    assert SCHEMA_WITH_INCIDENTS == json_dict

    sarif_results = json_dict["runs"][0]["results"]

    # Check each found secret is correctly represented
    for sarif_result, secret in zip(sarif_results, result.secrets):
        check_sarif_result(
            sarif_result,
            scannable.content,
            scannable.filemode,
            secret,
            with_incident_details and known_incidents,
        )

    assert len(sarif_results) == len(scan_result.policy_breaks)
    check_rules(json_dict, sarif_results)
    check_fingerprints_are_unique(sarif_results)


PATCHES_AND_RESULTS = [
    (
        _MULTIPLE_SECRETS_PATCH,
        _MULTIPLE_SECRETS_SCAN_RESULT,
    ),
    (
        _MULTI_SECRET_ONE_LINE_FULL_PATCH,
        _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
    ),
    (
        _ONE_LINE_AND_MULTILINE_PATCH,
        _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
    ),
]


def test_sarif_output_for_nested_scan(init_secrets_engine_version):
    """
    GIVEN a scan results for 3 patches containing secrets
    WHEN SecretSARIFOutputHandler runs on it
    THEN it outputs a SARIF document pointing to the secrets
    """
    handler = SecretSARIFOutputHandler(
        verbose=True, secret_config=SecretConfig(show_secrets=False)
    )

    nested_scans = []
    contents = []
    filemodes = []
    for idx, (patch, scan_result) in enumerate(PATCHES_AND_RESULTS):
        commit = Commit.from_patch(patch, sha=f"abcd{idx}")
        scannable = next(commit.get_files())
        contents.append(scannable.content)
        filemodes.append(scannable.filemode)

        result = Result.from_scan_result(
            file=scannable, scan_result=scan_result, secret_config=SecretConfig()
        )
        results = Results(results=[result])
        scan = SecretScanCollection(id=f"nested{idx}", type="test", results=results)
        nested_scans.append(scan)

    scan = SecretScanCollection(id="scan", type="test", scans=nested_scans)

    output = handler._process_scan_impl(scan)
    json_dict = json.loads(output)

    assert SCHEMA_WITH_INCIDENTS == json_dict

    # Create a flat list of secrets
    secrets = sum((s.results.results[0].secrets for s in scan.scans), [])

    # Check each found secret is correctly represented
    sarif_results = json_dict["runs"][0]["results"]
    for content, filemode, sarif_result, secret in zip(
        contents, filemodes, sarif_results, secrets
    ):
        check_sarif_result(sarif_result, content, filemode, secret)

    assert len(sarif_results) == len(secrets)
    check_rules(json_dict, sarif_results)
    check_fingerprints_are_unique(sarif_results)


def check_rules(json_dict: Dict[str, Any], sarif_results: List[Dict[str, Any]]) -> None:
    """Every result references a rule declared in driver.rules."""
    rules = json_dict["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [rule["id"] for rule in rules]

    # Rule ids are unique
    assert len(rule_ids) == len(set(rule_ids))

    for sarif_result in sarif_results:
        rule_id = sarif_result["ruleId"]
        rule_index = sarif_result["ruleIndex"]
        assert 0 <= rule_index < len(rules)
        assert rule_ids[rule_index] == rule_id
        # Rules only carry the minimal set of properties
        assert set(rules[rule_index]).issubset({"id", "helpUri"})


def check_fingerprints_are_unique(sarif_results: List[Dict[str, Any]]) -> None:
    """No two results share all their partial fingerprints."""
    fingerprint_sets = [
        tuple(sorted(result["partialFingerprints"].items())) for result in sarif_results
    ]
    assert len(fingerprint_sets) == len(set(fingerprint_sets))


def check_sarif_result(
    sarif_result: Dict[str, Any],
    content: str,
    filemode: Any,
    secret: Secret,
    contains_incident_details: bool = False,
):
    """Check sarif_result contains a representation of policy_break, applied to content"""

    # Check the secret name
    secret_name = sarif_result["ruleId"]
    assert secret_name == secret.detector_display_name

    # Check the uri is a plain document path, without any internal
    # commit:// / file:// URL scheme
    uri = sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "://" not in uri

    # Check the matches point to the right part of the content. Regions use the
    # real line numbers of the scanned document (Line.pre_index / post_index),
    # not patch-relative indices.
    lines = get_lines_from_content(content, filemode)
    expected_matches = {m.match_type: m.match for m in secret.matches}

    actual_matches = {}
    for location in sarif_result["relatedLocations"]:
        match_name = location["message"]["text"]
        region = location["physicalLocation"]["region"]
        matched_text = get_content_from_region(lines, region)
        actual_matches[match_name] = matched_text

    # Check that the markdown message contains the correct is_vaulted information
    markdown_message = sarif_result["message"]["markdown"]
    if secret.is_vaulted:
        expected_vault_text = "Secret found in vault: Yes"
    else:
        expected_vault_text = "Secret found in vault: No"
    assert (
        expected_vault_text in markdown_message
    ), f"Expected '{expected_vault_text}' in markdown message, but got: {markdown_message}"

    if contains_incident_details:
        assert (
            "properties" in sarif_result
            and "incidentDetails" in sarif_result["properties"]
        )
        SecretIncident(**sarif_result["properties"]["incidentDetails"])
    else:
        assert "incidentDetails" not in sarif_result

    assert actual_matches == expected_matches

    # The secret/v1 fingerprint is the unmodified ignore sha, identical to what
    # the JSON output exposes
    assert (
        sarif_result["partialFingerprints"][IGNORE_SHA_FINGERPRINT_KEY]
        == secret.get_ignore_sha()
    )

    # Regions point at the same real line numbers as the JSON occurrences and
    # text output
    primary_region = sarif_result["locations"][0]["physicalLocation"]["region"]
    assert primary_region["startLine"] == min(m.line_start for m in secret.matches)
    assert primary_region["endLine"] == max(m.line_end for m in secret.matches)
    for related_location, match in zip(
        sarif_result["relatedLocations"], secret.matches
    ):
        region = related_location["physicalLocation"]["region"]
        assert region["startLine"] == match.line_start
        assert region["endLine"] == match.line_end


class RegionDict(TypedDict):
    startLine: int
    startColumn: int
    endLine: int
    endColumn: int


def get_content_from_region(lines: List[Any], region: RegionDict) -> str:
    """Extract the matched text using SARIF regions expressed in real document
    line numbers. `lines` are the Line objects built from the scanned content,
    so Line.pre_index / post_index are the line numbers used in the region.
    """
    region_lines = [
        line
        for line in lines
        if (line.pre_index or line.post_index)
        in range(region["startLine"], region["endLine"] + 1)
    ]
    assert len(region_lines) == region["endLine"] - region["startLine"] + 1

    start_column = region["startColumn"] - 1
    # endColumn is 1-based and points to the character after the match, so it
    # needs to be decreased by 1
    end_column = region["endColumn"] - 1

    contents = [line.content for line in region_lines]
    # Cut start and end. Do the end first because if we cut the start first then
    # `end_column` will be invalid for 1-line regions
    contents[-1] = contents[-1][:end_column]
    contents[0] = contents[0][start_column:]
    return "\n".join(contents)


@pytest.mark.parametrize(
    "vault_type,vault_name,vault_path,vault_path_count,expected_messages",
    [
        (None, None, None, None, []),
        (
            "HashiCorp Vault",
            "vault.example.org",
            "/path/to/secret",
            1,
            [
                "Vault Type: HashiCorp Vault",
                "Vault Name: vault.example.org",
                "Secret Path: /path/to/secret",
            ],
        ),
        (
            "HashiCorp Vault",
            "vault.example.org",
            "/path/to/secret",
            4,
            [
                "Vault Type: HashiCorp Vault",
                "Vault Name: vault.example.org",
                "Secret Path: /path/to/secret",
            ],
        ),
        (
            "HashiCorp Vault",
            "vault.example.org",
            "/path/to/secret",
            1,
            [
                "Vault Type: HashiCorp Vault",
                "Vault Name: vault.example.org",
                "Secret Path: /path/to/secret",
            ],
        ),
    ],
)
def test_vault_path_in_sarif_output(
    init_secrets_engine_version,
    vault_type,
    vault_name,
    vault_path,
    vault_path_count,
    expected_messages,
):
    """
    GIVEN a secret with vault information
    WHEN it is passed to the SARIF output handler
    THEN the vault information is included in the markdown message
    """
    secret_config = SecretConfig()
    scannable = ScannableFactory()
    policy_break = PolicyBreakFactory(
        content=scannable.content,
        is_vaulted=vault_type is not None,
        vault_type=vault_type,
        vault_name=vault_name,
        vault_path=vault_path,
        vault_path_count=vault_path_count,
    )

    result = Result.from_scan_result(
        scannable, ScanResultFactory(policy_breaks=[policy_break]), secret_config
    )

    handler = SecretSARIFOutputHandler(
        verbose=True, secret_config=SecretConfig(show_secrets=False)
    )

    output = handler._process_scan_impl(
        SecretScanCollection(
            id="scan", type="scan", results=Results(results=[result], errors=[])
        )
    )

    json_dict = json.loads(output)
    sarif_results = json_dict["runs"][0]["results"]

    assert len(sarif_results) == 1
    markdown_message = sarif_results[0]["message"]["markdown"]

    # Check that all expected messages are present
    for expected_message in expected_messages:
        assert expected_message in markdown_message


def _make_extended_match(
    match: str,
    match_type: str,
    span_line_start: int,
    span_line_end: int,
    real_line_start: int,
    real_line_end: int,
    column_start: int = 0,
    column_end: int | None = None,
):
    """Build an ExtendedMatch without scanning, with distinct patch-relative
    span indices and real document line numbers."""
    if column_end is None:
        column_end = len(match)
    lines_with_secret = [Line(content=match, is_patch=True)]
    return ExtendedMatch(
        span=MatchSpan(
            line_index_start=span_line_start,
            line_index_end=span_line_end,
            column_index_start=column_start,
            column_index_end=column_end,
        ),
        lines_before_secret=[],
        lines_with_secret=lines_with_secret,
        lines_after_secret=[],
        match=match,
        index_start=column_start,
        index_end=column_end - 1,
        match_type=match_type,
        line_start=real_line_start,
        line_end=real_line_end,
        pre_line_start=real_line_start,
        pre_line_end=real_line_end,
        post_line_start=real_line_start,
        post_line_end=real_line_end,
    )


def _make_result(url, path, filemode, secrets):
    return SecretResult(
        filename=url,
        filemode=filemode,
        path=Path(path),
        url=url,
        secrets=secrets,
        ignored_secrets_count_by_kind=Counter(),
    )


def _make_secret(matches, detector="MySQL Assignment"):
    return Secret(
        detector_display_name=detector,
        detector_name="mysql_assignment",
        detector_group_name="mysql_credentials",
        documentation_url="https://example.com/docs/mysql",
        validity="valid",
        known_secret=False,
        incident_url=None,
        matches=matches,
        ignore_reason=None,
        diff_kind=None,
        is_vaulted=False,
        vault_type=None,
        vault_name=None,
        vault_path=None,
        vault_path_count=None,
    )


def _run_sarif(result):
    scan = SecretScanCollection(
        id="scan", type="test", results=Results(results=[result])
    )
    handler = SecretSARIFOutputHandler(
        verbose=True, secret_config=SecretConfig(show_secrets=False)
    )
    return json.loads(handler._process_scan_impl(scan))


def test_sarif_uses_real_document_line_numbers_not_patch_indices(
    init_secrets_engine_version,
):
    """
    GIVEN a patch whose hunk starts far from line 1, so patch-relative line
          indices differ from real document line numbers
    WHEN the SARIF output is generated
    THEN the regions use the same real line numbers as JSON occurrences and the
         text output (ExtendedMatch.line_start / line_end)
    """
    match = _make_extended_match(
        match="sg_key",
        match_type="apikey",
        # The match is the 2nd line of the patch content sent to the engine...
        span_line_start=1,
        span_line_end=1,
        # ...but line 151 of the real document
        real_line_start=151,
        real_line_end=151,
    )
    result = _make_result(
        url="commit://deadbeef/svc/creds.py",
        path="svc/creds.py",
        filemode=Filemode.MODIFY,
        secrets=[_make_secret([match])],
    )

    json_dict = _run_sarif(result)
    region = json_dict["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "region"
    ]
    assert region["startLine"] == 151
    assert region["endLine"] == 151

    related_region = json_dict["runs"][0]["results"][0]["relatedLocations"][0][
        "physicalLocation"
    ]["region"]
    assert related_region["startLine"] == 151


def test_sarif_uri_strips_internal_url_schemes(init_secrets_engine_version):
    """
    GIVEN results coming from commit-range and absolute-path scans
    WHEN the SARIF output is generated
    THEN artifact uris are plain repository-relative paths with no commit:// or
         file:// prefix, matching the JSON filename and text output
    """

    commit_match = _make_extended_match("a-secret", "apikey", 0, 0, 20, 20)
    commit_result = _make_result(
        url="commit://deadbeef/svc/creds.py",
        path="svc/creds.py",
        filemode=Filemode.MODIFY,
        secrets=[_make_secret([commit_match])],
    )

    file_match = _make_extended_match("b-secret", "apikey", 0, 0, 3, 3)
    file_result = _make_result(
        url="file:///home/me/repo/svc/creds.py",
        path="/home/me/repo/svc/creds.py",
        filemode=Filemode.FILE,
        secrets=[_make_secret([file_match], detector="AWS Keys")],
    )

    scan = SecretScanCollection(
        id="scan",
        type="test",
        results=Results(results=[commit_result, file_result]),
    )
    handler = SecretSARIFOutputHandler(
        verbose=True, secret_config=SecretConfig(show_secrets=False)
    )
    json_dict = json.loads(handler._process_scan_impl(scan))

    uris = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in json_dict["runs"][0]["results"]
    ]
    assert uris == ["svc/creds.py", "/home/me/repo/svc/creds.py"]
    assert all("://" not in uri for uri in uris)


def test_sarif_keeps_docset_document_id(init_secrets_engine_version):
    """
    GIVEN a docset scan whose document id is a full URL
    WHEN the SARIF output is generated
    THEN the artifact uri is the document id, unchanged (same identifier as the
         text and JSON outputs)
    """

    document_id = "https://github.com/owner/repo/issues/4#issuecomment-10069"
    match = _make_extended_match("c-secret", "apikey", 0, 0, 1, 1)
    result = _make_result(
        url=document_id,
        path=document_id,
        filemode=Filemode.FILE,
        secrets=[_make_secret([match])],
    )

    json_dict = _run_sarif(result)
    uri = json_dict["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == document_id


def test_sarif_results_with_shared_ignore_sha_have_unique_fingerprints(
    init_secrets_engine_version,
):
    """
    GIVEN several secrets with identical matches (so the JSON output groups them
          into one incident and they share the same ignore_sha)
    WHEN the SARIF output is generated
    THEN each secret gets its own result, secret/v1 stays the ignore sha, and the
         full partialFingerprints of every result are unique
    """

    # Same match content -> same ignore sha, but different real locations
    secrets = []
    for real_line in (20, 45, 80, 132):
        match = _make_extended_match(
            "duplicated-secret", "apikey", 0, 0, real_line, real_line
        )
        secrets.append(_make_secret([match]))

    ignore_shas = {secret.get_ignore_sha() for secret in secrets}
    assert len(ignore_shas) == 1  # sanity check: they really share an ignore sha
    shared_ignore_sha = ignore_shas.pop()

    result = _make_result(
        url="commit://deadbeef/svc/creds.py",
        path="svc/creds.py",
        filemode=Filemode.MODIFY,
        secrets=secrets,
    )
    json_dict = _run_sarif(result)
    sarif_results = json_dict["runs"][0]["results"]

    # One SARIF result per secret (each JSON incident occurrence)
    assert len(sarif_results) == len(secrets)

    # secret/v1 is the unmodified ignore sha
    assert all(
        r["partialFingerprints"][IGNORE_SHA_FINGERPRINT_KEY] == shared_ignore_sha
        for r in sarif_results
    )

    # But the full fingerprint sets are all different
    fingerprint_sets = [
        tuple(sorted(r["partialFingerprints"].items())) for r in sarif_results
    ]
    assert len(set(fingerprint_sets)) == len(sarif_results)

    # And the occurrence hashes themselves are unique
    occurrence_hashes = [
        r["partialFingerprints"][UNIQUE_FINGERPRINT_KEY] for r in sarif_results
    ]
    assert len(set(occurrence_hashes)) == len(occurrence_hashes)


def test_sarif_result_count_matches_policy_breaks_and_rules_are_referenced(
    init_secrets_engine_version,
):
    """
    GIVEN secrets from several detectors
    WHEN the SARIF output is generated
    THEN driver.rules declares one rule per detector and every result references
         a valid ruleIndex
    """

    secrets = [
        _make_secret(
            [_make_extended_match("s1", "apikey", 0, 0, 2, 2)],
            detector="Detector A",
        ),
        _make_secret(
            [_make_extended_match("s2", "password", 0, 0, 5, 5)],
            detector="Detector B",
        ),
        _make_secret(
            [_make_extended_match("s3", "token", 0, 0, 9, 9)],
            detector="Detector A",
        ),
    ]
    result = _make_result(
        url="svc/creds.py",
        path="svc/creds.py",
        filemode=Filemode.FILE,
        secrets=secrets,
    )
    json_dict = _run_sarif(result)
    run = json_dict["runs"][0]
    rules = run["tool"]["driver"]["rules"]

    assert [rule["id"] for rule in rules] == ["Detector A", "Detector B"]
    # First rule carries the detector documentation url
    assert rules[0]["helpUri"] == "https://example.com/docs/mysql"

    for sarif_result in run["results"]:
        rule = rules[sarif_result["ruleIndex"]]
        assert rule["id"] == sarif_result["ruleId"]


def test_sarif_matches_json_incident_identity(init_secrets_engine_version):
    """
    GIVEN one scanned document with one secret
    WHEN both SARIF and JSON outputs are generated
    THEN the SARIF result points at the same path and line as the JSON incident
         occurrence, and carries the same ignore sha
    """

    match = _make_extended_match(
        "json-sarif-secret", "apikey", 0, 0, 20, 20, column_start=4, column_end=21
    )
    secret = _make_secret([match])
    result = _make_result(
        url="commit://deadbeef/svc/creds.py",
        path="svc/creds.py",
        filemode=Filemode.MODIFY,
        secrets=[secret],
    )

    sarif_dict = _run_sarif(result)
    sarif_result = sarif_dict["runs"][0]["results"][0]

    json_handler = SecretJSONOutputHandler(
        verbose=True, secret_config=SecretConfig(show_secrets=False)
    )
    json_dict = json.loads(
        json_handler._process_scan_impl(
            SecretScanCollection(
                id="scan", type="test", results=Results(results=[result])
            )
        )
    )
    entity = json_dict["entities_with_incidents"][0]
    incident = entity["incidents"][0]
    occurrence = incident["occurrences"][0]

    # Same repository-relative path
    assert (
        sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == entity["filename"]
    )
    # Same real line number
    region = sarif_result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == occurrence["line_start"] == 20
    # Same ignore sha
    assert (
        sarif_result["partialFingerprints"][IGNORE_SHA_FINGERPRINT_KEY]
        == incident["ignore_sha"]
    )
