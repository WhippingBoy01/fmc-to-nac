"""Async read-oriented Cisco FMC REST API client."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)


class FMCAPIError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None, details: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


class FMCClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify: bool | str = True,
        timeout: float = 60.0,
        domain_uuid: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self._domain_uuid = domain_uuid
        self._token: str | None = None
        self._client = httpx.AsyncClient(verify=self.verify, timeout=self.timeout)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "FMCClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def login(self) -> dict[str, Any]:
        url = f"{self.base_url}/api/fmc_platform/v1/auth/generatetoken"
        resp = await self._client.post(url, auth=(self.username, self.password))
        if resp.status_code not in (200, 204):
            raise FMCAPIError(
                f"FMC authentication failed ({resp.status_code}).",
                status_code=resp.status_code,
                details=_safe_json(resp) or resp.text[:2000],
            )
        token = resp.headers.get("X-auth-access-token")
        if not token:
            raise FMCAPIError("FMC authentication response did not include X-auth-access-token.")
        self._token = token
        domain = self._domain_uuid or resp.headers.get("DOMAIN_UUID")
        if not domain:
            domains = resp.headers.get("DOMAINS")
            if domains:
                try:
                    parsed = json.loads(domains)
                    if isinstance(parsed, list) and parsed:
                        domain = parsed[0].get("uuid")
                except Exception:
                    pass
        if not domain:
            domain = await self._discover_domain()
        if not domain:
            raise FMCAPIError("Could not determine FMC domain UUID. Set FMC_DOMAIN_UUID.")
        self._domain_uuid = domain
        return {"domain_uuid": domain}

    async def _discover_domain(self) -> str | None:
        if not self._token:
            return None
        url = f"{self.base_url}/api/fmc_platform/v1/info/domain"
        resp = await self._client.get(url, headers=self._auth_headers())
        if resp.status_code != 200:
            return None
        data = _safe_json(resp)
        items = (data or {}).get("items") or []
        for item in items:
            if item.get("type") == "Domain" and item.get("uuid"):
                return item["uuid"]
        if items and items[0].get("uuid"):
            return items[0]["uuid"]
        return None

    def _auth_headers(self) -> dict[str, str]:
        if not self._token:
            raise FMCAPIError("Not authenticated.")
        return {"X-auth-access-token": self._token, "Accept": "application/json"}

    async def ensure_login(self) -> None:
        if not self._token or not self._domain_uuid:
            await self.login()

    async def domain_uuid(self) -> str:
        await self.ensure_login()
        assert self._domain_uuid
        return self._domain_uuid

    async def config_path(self, suffix: str) -> str:
        domain = await self.domain_uuid()
        suffix = "/" + suffix.lstrip("/")
        return f"/api/fmc_config/v1/domain/{domain}{suffix}"

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        retry_auth: bool = True,
        allow_404: bool = False,
    ) -> Any:
        await self.ensure_login()
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        resp = await self._client.request(method, url, headers=self._auth_headers(), params=params)
        if resp.status_code == 401 and retry_auth:
            self._token = None
            await self.login()
            return await self.request(method, path, params=params, retry_auth=False, allow_404=allow_404)
        if resp.status_code == 404 and allow_404:
            return None
        if resp.status_code >= 400:
            raise FMCAPIError(
                f"FMC API {method} {path} failed ({resp.status_code}).",
                status_code=resp.status_code,
                details=_safe_json(resp) or resp.text[:4000],
            )
        if resp.status_code == 204 or not resp.content:
            return {"status": "ok", "http_status": resp.status_code}
        return _safe_json(resp)

    async def get(self, path: str, *, params: dict[str, Any] | None = None, allow_404: bool = False) -> Any:
        return await self.request("GET", path, params=params, allow_404=allow_404)

    async def get_all(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        limit: int = 1000,
        max_items: int = 10000,
        expanded: bool = False,
        allow_404: bool = False,
    ) -> list[dict[str, Any]]:
        offset = 0
        items: list[dict[str, Any]] = []
        base_params = dict(params or {})
        if expanded:
            base_params.setdefault("expanded", "true")
        while True:
            page_params = {**base_params, "offset": offset, "limit": limit}
            data = await self.get(path, params=page_params, allow_404=allow_404)
            if data is None:
                return []
            page_items = (data or {}).get("items") or []
            if isinstance(page_items, list):
                items.extend(page_items)
            paging = (data or {}).get("paging") or {}
            count = paging.get("count")
            if isinstance(count, int) and offset + limit >= count:
                break
            if not page_items or len(items) >= max_items:
                break
            if not paging and len(page_items) < limit:
                break
            offset += limit
        return items[:max_items]

    async def get_all_domains(self) -> list[dict[str, Any]]:
        await self.ensure_login()
        data = await self.get(f"{self.base_url}/api/fmc_platform/v1/info/domain")
        return (data or {}).get("items") or []


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None
