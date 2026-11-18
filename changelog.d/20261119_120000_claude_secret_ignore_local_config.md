### Fixed

- `ggshield secret ignore` no longer dumps the whole merged configuration into
  the local `.gitguardian.yaml`: it now only appends the new entries to the
  `secret.ignored_matches` section, so user-specific settings from the global
  configuration (such as `exit_zero`, `insecure`, `instance` or
  `secret.show_secrets`) are not copied into the repository anymore.
- `ggshield secret ignore` run from a repository subdirectory now writes to the
  local configuration file ggshield actually reads (at the repository root),
  instead of creating a `.gitguardian.yaml` in the subdirectory that was never
  loaded. Ignoring the same secret twice no longer duplicates its entry.
