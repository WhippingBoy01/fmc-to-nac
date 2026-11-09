"""Export FMC VPNs and integrations (best-effort)."""

from __future__ import annotations

from typing import Any

from ..nac import prune
from .base import ExportContext


def _base(suffix: str, ctx: ExportContext) -> str:
    return f"/api/fmc_config/v1/domain/{ctx.domain_uuid}/{suffix.lstrip('/')}"


async def export_vpns(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, suffix in [
        ("site_to_site_vpns", "policy/ftds2svpns"),
        ("remote_access_vpns", "policy/ravpns"),
    ]:
        try:
            items = await ctx.client.get_all(_base(suffix, ctx), expanded=True, allow_404=True)
            mapped = []
            for item in items:
                if not item.get("name"):
                    continue
                m = {"name": item["name"]}
                if item.get("description"):
                    m["description"] = item["description"]
                # VPN configs are deeply nested; preserve best-effort expanded structure minus metadata.
                extra = prune({k: v for k, v in item.items() if k not in {"name", "description"}}, strip_keys={"id", "links", "metadata", "version"})
                if extra:
                    m.update(extra)
                mapped.append(m)
            if mapped:
                out[key] = mapped
                ctx.count(f"vpns.{key}", len(mapped))
        except Exception as exc:
            ctx.warn(f"vpns.{key}: {exc}")
    return out


async def export_integrations(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, suffix in [
        ("ad_ldap_realms", "integration/realms"),
        ("local_realms", "integration/localrealms"),
        ("duo_identity_sources", "integration/externalidentitysources"),
    ]:
        try:
            items = await ctx.client.get_all(_base(suffix, ctx), expanded=True, allow_404=True)
            mapped = []
            for item in items:
                if not item.get("name"):
                    continue
                m = {"name": item["name"]}
                if item.get("description"):
                    m["description"] = item["description"]
                # For AD realms, keep safe config fields; avoid secrets if any appear.
                for k in ["type", "realmType", "enabled", "directoryConfigurations", "adPrimaryDomain", "authProtocol"]:
                    if item.get(k) is not None:
                        m[k] = prune(item[k], strip_keys={"id", "links", "metadata", "version"})
                mapped.append(prune(m))
            if mapped:
                out[key] = mapped
                ctx.count(f"integrations.{key}", len(mapped))
        except Exception as exc:
            ctx.warn(f"integrations.{key}: {exc}")
    return out
