"""Exporter base helpers."""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from ..fmc_client import FMCClient

log = logging.getLogger(__name__)


@dataclass
class ExportContext:
    client: FMCClient
    domain_uuid: str
    domain_name: str
    exclude: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    exported: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        log.warning(msg)

    def count(self, key: str, n: int) -> None:
        if n:
            self.exported[key] = self.exported.get(key, 0) + n

    def is_excluded(self, path: str) -> bool:
        if not self.exclude:
            return False
        p = path.lower()
        for pat in self.exclude:
            pat = pat.lower().strip()
            if not pat:
                continue
            if p == pat or p.startswith(pat + "."):
                return True
            if fnmatch.fnmatch(p, pat):
                return True
        return False

    def skip(self, key: str, n: int = 1) -> None:
        if n:
            self.skipped[key] = self.skipped.get(key, 0) + n
            log.info("Excluded %s (%s)", key, n)


ExportFunc = Callable[[ExportContext], Awaitable[dict[str, Any]]]
