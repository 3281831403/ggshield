### Fixed

- `--all-secrets` is display-only again: it no longer changes the verdict. A
  scan whose hits are all ignored exits 0 instead of 1, the AI hook allows
  instead of denying, and a scan with unscanned files keeps its specific exit
  code (4) instead of being degraded to a generic failure. Ignored hits are
  still printed with their `Ignored:` reason. Docker layer caching also no
  longer treats an ignored-only layer as dirty, so the layer cache is written
  as intended.
