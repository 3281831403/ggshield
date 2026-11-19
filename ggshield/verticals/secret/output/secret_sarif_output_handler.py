import hashlib
import json
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pygitguardian.client import VERSIONS
from pygitguardian.models import SecretIncident

from ggshield import __version__ as ggshield_version
from ggshield.core.text_utils import pluralize

from ..extended_match import ExtendedMatch
from ..secret_scan_collection import Result, Secret, SecretScanCollection
from .secret_output_handler import SecretOutputHandler


SCHEMA_URL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

# Key of the partial fingerprint holding the ggshield ignore sha. The value is
# always the exact output of `Secret.get_ignore_sha()`, so it stays identical to
# the ignore_sha field of JSON incidents and to the "Secret SHA" line of text
# reports.
IGNORE_SHA_FINGERPRINT_KEY = "secret/v1"
# Key of the partial fingerprint making every SARIF result unique. GitHub code
# scanning deduplicates results sharing all their partial fingerprints, so two
# occurrences with the same ignore sha (the JSON format groups them into one
# incident) must still produce distinct results.
UNIQUE_FINGERPRINT_KEY = "ggshield/result/v1"


class SecretSARIFOutputHandler(SecretOutputHandler):

    def _process_scan_impl(self, scan: SecretScanCollection) -> str:
        incident_details = (
            scan.get_incident_details(self.client)
            if self.with_incident_details and self.client
            else {}
        )
        all_results = list(scan.get_all_results())
        rules, rule_index_by_id = _create_rules(all_results)
        dct = {
            "version": "2.1.0",
            "$schema": SCHEMA_URL,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "organization": "GitGuardian",
                            "name": "ggshield",
                            "informationUri": "https://github.com/GitGuardian/ggshield",
                            "version": ggshield_version,
                            "rules": rules,
                        },
                        "extensions": [
                            {
                                "name": "secret",
                                "version": VERSIONS.secrets_engine_version,
                            }
                        ],
                    },
                    "results": list(
                        _create_sarif_results(
                            all_results, rule_index_by_id, incident_details
                        )
                    ),
                }
            ],
        }
        return json.dumps(dct)


def _create_rules(
    results: Iterable[Result],
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Declares one SARIF rule per detector, in first-seen order.

    Returns the rules and a mapping from detector display name to their index,
    so that results can reference them through `ruleIndex`.
    """
    rule_index_by_id: Dict[str, int] = {}
    for result in results:
        for secret in result.secrets:
            rule_id = secret.detector_display_name
            if rule_id not in rule_index_by_id:
                rule_index_by_id[rule_id] = len(rule_index_by_id)

    # Recover the documentation url of the first secret using each rule id.
    documentation_url_by_id: Dict[str, Optional[str]] = {}
    for result in results:
        for secret in result.secrets:
            documentation_url_by_id.setdefault(
                secret.detector_display_name, secret.documentation_url
            )

    rules: List[Dict[str, Any]] = []
    for rule_id in rule_index_by_id:
        rule: Dict[str, Any] = {"id": rule_id}
        documentation_url = documentation_url_by_id.get(rule_id)
        if documentation_url:
            rule["helpUri"] = documentation_url
        rules.append(rule)
    return rules, rule_index_by_id


def _create_sarif_results(
    results: Iterable[Result],
    rule_index_by_id: Dict[str, int],
    incident_details: Dict[str, SecretIncident],
) -> Iterable[Dict[str, Any]]:
    """
    Creates SARIF result dicts for our Result instances. Creates one SARIF
    result dict per secret (each JSON incident occurrence gets its own result).
    """
    for result in results:
        for secret in result.secrets:
            yield _create_sarif_result_dict(
                result, secret, rule_index_by_id, incident_details
            )


def _artifact_uri(result: Result) -> str:
    """Location shared by the text and JSON outputs, without any internal URL
    scheme prefix.

    - commit-range / staged / patch scans: `commit://<sha>/<path>` -> `<path>`,
      a repository-relative path (the `<sha>` part is not part of the document
      location and differs between scans of the same file)
    - absolute path scans: `file:///<path>` -> `<path>`, matching the absolute
      path used by the text and JSON outputs
    - relative path scans and docset document ids: returned unchanged
    """
    parsed = urllib.parse.urlparse(result.url)
    if parsed.scheme == "commit":
        # `netloc` is the sha (or "staged" / "patch"); `path` starts with "/"
        return urllib.parse.unquote(parsed.path.lstrip("/"))
    if parsed.scheme == "file":
        # Keep the absolute document path itself: this is exactly what the text
        # and JSON outputs display, only the internal file:// scheme is dropped
        return urllib.parse.unquote(parsed.path)
    # Relative file paths are already plain relative paths, and StringScannable
    # instances (docset document ids, docker layers, ...) use their own
    # identifier as url: keep them untouched.
    return result.url


def _match_real_line_span(match: ExtendedMatch) -> Tuple[int, int]:
    """1-based line numbers of the match in the scanned document.

    `MatchSpan` indices are relative to the content ggshield sends to the scan
    engine: for a patch this is the patch itself, so they do not match the real
    line numbers shown by the text and JSON outputs when a hunk does not start
    at line 1. `ExtendedMatch.line_start` / `line_end` hold the real document
    line numbers instead.
    """
    return match.line_start, match.line_end


def _create_sarif_result_dict(
    result: Result,
    secret: Secret,
    rule_index_by_id: Dict[str, int],
    incident_details: Dict[str, SecretIncident],
) -> Dict[str, Any]:
    # Prepare message with links to the related location for each match
    matches_str = ", ".join(
        f"[{m.match_type}]({id})" for id, m in enumerate(secret.matches)
    )
    matches_li = "\n".join(
        f"- [{m.match_type}]({id})" for id, m in enumerate(secret.matches)
    )
    extended_matches = secret.matches
    message = (
        f"Secret detected: {secret.detector_display_name}.\nMatches: {matches_str}"
    )
    if secret.documentation_url:
        markdown_message = f"Secret detected: [{secret.detector_display_name}]({secret.documentation_url})"
    else:
        markdown_message = f"Secret detected: {secret.detector_display_name}"

    if secret.is_vaulted:
        if secret.vault_path_count is None:
            markdown_message += "\nSecret found in vault: Yes"
        else:
            vault_count_text = f"({secret.vault_path_count} {pluralize('location', secret.vault_path_count)})"
            markdown_message += f"\nSecret found in vault: Yes {vault_count_text}"
            markdown_message += f"\nVault Type: {secret.vault_type}"
            markdown_message += f"\nVault Name: {secret.vault_name}"
            markdown_message += f"\nSecret Path: {secret.vault_path}"
    else:
        markdown_message += "\nSecret found in vault: No"

    markdown_message += f"\nMatches:\n{matches_li}"

    uri = _artifact_uri(result)

    # Create dict
    dct: Dict[str, Any] = {
        "ruleId": secret.detector_display_name,
        "ruleIndex": rule_index_by_id[secret.detector_display_name],
        "level": "error",
        "message": {
            "text": message,
            "markdown": markdown_message,
        },
        "locations": [
            _create_location_dict(uri, extended_matches),
        ],
        "relatedLocations": [
            _create_related_location_dict(uri, id, m)
            for id, m in enumerate(extended_matches)
        ],
        # The fingerprint identifies the occurrence, so it uses the full
        # internal document url (including the commit sha): the same file
        # scanned at two commits would otherwise collide, even though their
        # display uris are intentionally identical.
        "partialFingerprints": _create_partial_fingerprints(result.url, secret),
    }
    if secret.incident_url:
        dct["hostedViewerUri"] = secret.incident_url
        details = incident_details.get(secret.incident_url)
        if details is not None:
            dct["properties"] = {"incidentDetails": details.to_dict()}
    return dct


def _create_partial_fingerprints(document_url: str, secret: Secret) -> Dict[str, str]:
    """Builds the partial fingerprints of a SARIF result.

    `secret/v1` is the ggshield ignore sha and must stay identical to the value
    found in the JSON output. `ggshield/result/v1` extends it with the full
    document url (including the commit sha) and the match locations so that
    every result, including occurrences sharing an ignore sha, gets a unique
    fingerprint.
    """
    ignore_sha = secret.get_ignore_sha()
    location = "".join(
        f"{document_url}:{match.line_start}:{match.line_end}:"
        f"{match.span.column_index_start}:{match.span.column_index_end}:"
        f"{match.match_type}"
        for match in secret.matches
    )
    occurrence_hash = hashlib.sha256(location.encode("UTF-8")).hexdigest()
    return {
        IGNORE_SHA_FINGERPRINT_KEY: ignore_sha,
        UNIQUE_FINGERPRINT_KEY: occurrence_hash,
    }


def _create_location_dict(
    uri: str,
    matches: List[ExtendedMatch],
) -> Dict[str, Any]:
    # Create a span from the start of the first match to the end of the last
    # match, using real document line numbers
    start_line = min(m.line_start for m in matches)
    end_line = max(m.line_end for m in matches)
    first_match = min(matches, key=lambda m: (m.line_start, m.span.column_index_start))
    last_match = max(matches, key=lambda m: (m.line_end, m.span.column_index_end))
    region = {
        "startLine": start_line,
        "startColumn": first_match.span.column_index_start + 1,
        "endLine": end_line,
        "endColumn": last_match.span.column_index_end + 1,
    }

    return {"physicalLocation": _create_physical_location_dict(uri, region)}


def _create_related_location_dict(
    uri: str,
    id: int,
    match: ExtendedMatch,
) -> Dict[str, Any]:
    line_start, line_end = _match_real_line_span(match)
    region = {
        "startLine": line_start,
        "startColumn": match.span.column_index_start + 1,
        "endLine": line_end,
        "endColumn": match.span.column_index_end + 1,
    }
    return {
        "id": id,
        "physicalLocation": _create_physical_location_dict(uri, region),
        "message": {"text": match.match_type},
    }


def _create_physical_location_dict(uri: str, region: Dict[str, int]) -> Dict[str, Any]:
    return {
        "artifactLocation": {
            "uri": uri,
        },
        "region": region,
    }
