import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List

from ggshield.core import ui
from ggshield.core.constants import CACHE_PATH
from ggshield.core.types import IgnoredMatch
from ggshield.utils.git_shell import gitignore, is_gitignored


SECRETS_CACHE_KEY = "last_found_secrets"


class Cache:
    def __init__(self) -> None:
        # Anchor the cache to the directory ggshield was invoked from: some
        # scan commands chdir() into the scanned repository, and a relative
        # path would follow them and be written there.
        self.cache_path = Path(CACHE_PATH).resolve()
        self.last_found_secrets: List[IgnoredMatch] = []
        # Scan commands run concurrent batches which all share this instance:
        # the lock keeps their writes from interleaving, and _scan_started
        # ensures the reset for a new scan happens only once per process, so a
        # batch cannot wipe the secrets another batch just recorded.
        self._lock = threading.Lock()
        self._scan_started = False
        self.load_cache()

    def load_cache(self) -> None:
        # The gitignore helpers work on paths relative to the CWD
        try:
            display_path = self.cache_path.relative_to(Path.cwd())
        except ValueError:
            display_path = self.cache_path

        if self.cache_path.is_file() and is_gitignored(display_path) is False:
            gitignore(display_path)

        if not self.cache_path.is_file() or self.cache_path.stat().st_size == 0:
            return

        try:
            f = self.cache_path.open()
        except PermissionError:
            # Hotfix: for the time being we skip cache handling if permission denied
            return
        with f:
            try:
                _cache: Dict[str, Any] = json.load(f)
            except Exception as e:
                # A corrupted cache must not break the command: ignore it
                ui.display_warning(
                    f"Could not parse {self.cache_path}, ignoring it:\n{str(e)}"
                )
                return
        try:
            self.update_cache(**_cache)
        except Exception as e:
            ui.display_warning(
                f"Could not read {self.cache_path}, ignoring it:\n{str(e)}"
            )

    def update_cache(self, **kwargs: Any) -> None:
        if SECRETS_CACHE_KEY in kwargs:
            self.last_found_secrets = [
                IgnoredMatch.from_dict(secret)
                for secret in kwargs.pop(SECRETS_CACHE_KEY)
            ]
        if kwargs:
            for key in kwargs.keys():
                ui.display_warning(f'Unrecognized key in cache "{key}"')

    def to_dict(self) -> Dict[str, Any]:
        return {
            SECRETS_CACHE_KEY: [secret.to_dict() for secret in self.last_found_secrets]
        }

    def save(self) -> None:
        with self._lock:
            if not self.last_found_secrets:
                # The last scan found nothing: drop the previous run's cache so
                # `--last-found` does not resurrect it, but do not create the
                # file if there was none.
                try:
                    self.cache_path.unlink()
                except OSError:
                    pass
                return
            try:
                fd = os.open(
                    str(self.cache_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
                )
                f = os.fdopen(fd, "w")
            except OSError:
                # Hotfix: for the time being we skip cache handling if permission denied
                return
            with f:
                try:
                    json.dump(self.to_dict(), f)
                except Exception as e:
                    ui.display_warning(
                        f"Failed to save cache in {self.cache_path}:\n{str(e)}"
                    )

    def purge(self) -> None:
        with self._lock:
            self.last_found_secrets = []

    def start_scan(self) -> None:
        """
        Reset the recorded secrets for a new scan command. Only the first call
        of the process resets: concurrent scan batches share this cache, and a
        later reset would drop secrets an earlier batch just recorded.
        """
        with self._lock:
            if self._scan_started:
                return
            self._scan_started = True
            self.last_found_secrets = []

    def add_found_policy_break(
        self, break_type: str, ignore_sha: str, filename: str
    ) -> None:
        with self._lock:
            if not any(
                last_found.match == ignore_sha for last_found in self.last_found_secrets
            ):
                self.last_found_secrets.append(
                    IgnoredMatch(
                        name=f"{break_type} - {filename}",
                        match=ignore_sha,
                    )
                )


class ReadOnlyCache(Cache):
    """
    A version of Cache which does not write anything to the disk.
    """

    def save(self) -> None:  # pragma: no cover
        return None
