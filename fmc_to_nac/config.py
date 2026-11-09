"""Environment-based configuration for FMC to NaC export (read-only)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if not normalized:
        return default
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise ConfigError(f"Cannot interpret {value!r} as a boolean.")


@dataclass(frozen=True)
class Settings:
    host: str
    username: str
    password: str
    domain_uuid: str | None
    verify_ssl: bool
    ca_bundle: str | None
    timeout: float
    log_level: str

    @property
    def base_url(self) -> str:
        return self.host.rstrip("/")

    @property
    def verify(self) -> bool | str:
        return self.ca_bundle or self.verify_ssl


def load_settings(env_file: str | None = None) -> Settings:
    if env_file:
        load_dotenv(env_file, override=False)
    else:
        local = Path.cwd() / ".env"
        if local.is_file():
            load_dotenv(local, override=False)

    host = (os.getenv("FMC_HOST") or "").strip().rstrip("/")
    username = (os.getenv("FMC_USERNAME") or "").strip()
    password = os.getenv("FMC_PASSWORD") or ""
    if not host:
        raise ConfigError("FMC_HOST is required (for example https://fmc.example.local).")
    if not host.startswith("https://") and not host.startswith("http://"):
        raise ConfigError("FMC_HOST must include a scheme, for example https://fmc.example.local.")
    if not username or not password:
        raise ConfigError("FMC_USERNAME and FMC_PASSWORD are required.")

    ca_bundle = (os.getenv("FMC_CA_BUNDLE") or "").strip() or None
    if ca_bundle and not Path(ca_bundle).is_file():
        raise ConfigError(f"FMC_CA_BUNDLE does not exist: {ca_bundle}")

    return Settings(
        host=host,
        username=username,
        password=password,
        domain_uuid=(os.getenv("FMC_DOMAIN_UUID") or "").strip() or None,
        verify_ssl=_as_bool(os.getenv("FMC_VERIFY_SSL"), default=True),
        ca_bundle=ca_bundle,
        timeout=float(os.getenv("FMC_TIMEOUT") or "60"),
        log_level=(os.getenv("LOG_LEVEL") or "INFO").strip().upper(),
    )
