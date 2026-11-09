"""Helpers for building NetAsCode FMC YAML structures."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any


# Keys commonly returned by FMC API that are metadata/links rather than NaC config.
STRIP_KEYS = {
    "id",
    "links",
    "metadata",
    "version",
    "type",
}

SENSITIVE_KEY_RE = re.compile(
    r"(password|passphrase|secret|token|community|psk|pre_shared|private_key|privatekey|"
    r"registration_key|regkey|reg_key|enrollment|passcode|shared_secret)",
    re.IGNORECASE,
)


def prune(value: Any, *, strip_keys: set[str] | None = None) -> Any:
    """Recursively remove empty values and API metadata keys."""
    strip = strip_keys if strip_keys is not None else STRIP_KEYS
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if k in strip:
                continue
            pv = prune(v, strip_keys=strip)
            if pv in (None, "", [], {}):
                # Keep explicit false/0.
                if pv is False or pv == 0:
                    out[k] = pv
                continue
            out[k] = pv
        return out
    if isinstance(value, list):
        out_list = [prune(v, strip_keys=strip) for v in value]
        return [v for v in out_list if v not in (None, "", [], {}) or v is False or v == 0]
    return value


def redact(value: Any, replacement: str = "<REDACTED>") -> Any:
    """Redact values for sensitive-looking keys (best-effort)."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if SENSITIVE_KEY_RE.search(str(k)) and v not in (None, "", [], {}):
                out[k] = replacement if not isinstance(v, (dict, list)) else redact(v, replacement)
            else:
                out[k] = redact(v, replacement)
        return out
    if isinstance(value, list):
        return [redact(v, replacement) for v in value]
    return value


def ensure_domain(model: dict[str, Any], domain_name: str) -> dict[str, Any]:
    fmc = model.setdefault("fmc", {})
    domains = fmc.setdefault("domains", [])
    for d in domains:
        if d.get("name") == domain_name:
            return d
    d = {"name": domain_name}
    domains.append(d)
    return d


def extend_list(container: dict[str, Any], key: str, items: Iterable[dict[str, Any]]) -> None:
    lst = container.setdefault(key, [])
    lst.extend(items)


def ref_name(obj: Any) -> str | None:
    """Extract a name from an FMC reference/value."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return obj.get("name") or obj.get("literal") or obj.get("value")
    return None


def ref_names(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    out: list[str] = []
    for item in items:
        name = ref_name(item)
        if name:
            out.append(str(name))
    return out
