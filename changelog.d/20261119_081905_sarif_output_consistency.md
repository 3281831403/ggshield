### Fixed

- SARIF output is now consistent with the text and JSON outputs for the same
  finding. Artifact locations are plain document paths without the internal
  `commit://<sha>/` or `file:///` schemes, and regions use the real document
  line numbers (matching JSON occurrences and the text report) instead of
  patch-relative indices, including when a hunk does not start at line 1.
  `driver.rules` is now declared once per detector and referenced by every
  result through `ruleIndex`. Each result keeps the unchanged ignore sha in
  its `secret/v1` partial fingerprint and gets a unique `ggshield/result/v1`
  fingerprint, so occurrences sharing an ignore sha no longer collide. Exit
  codes, ignore sha values and docset document ids are unchanged.
