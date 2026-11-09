"""Export FMC system/domain-level NaC sections (best-effort)."""

from __future__ import annotations

from typing import Any

from ..nac import prune, ref_name
from .base import ExportContext


def _base(suffix: str, ctx: ExportContext) -> str:
    return f"/api/fmc_config/v1/domain/{ctx.domain_uuid}/{suffix.lstrip('/')}"


async def export_system(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    # Policy assignments (system-level in NaC module structure varies; export as data).
    try:
        pa = await ctx.client.get_all(_base("assignment/policyassignments", ctx), expanded=True, allow_404=True)
        if pa:
            mapped = []
            for item in pa:
                pol = item.get("policy") or {}
                targets = item.get("targets") or []
                m = {
                    "name": (pol.get("name") if isinstance(pol, dict) else None) or item.get("name"),
                    "policy_type": pol.get("type") if isinstance(pol, dict) else item.get("type"),
                    "targets": [t.get("name") for t in targets if isinstance(t, dict) and t.get("name")],
                }
                mapped.append(prune(m))
            if mapped:
                out["policy_assignments"] = mapped
                ctx.count("system.policy_assignments", len(mapped))
    except Exception as exc:
        ctx.warn(f"system.policy_assignments: {exc}")

    # Deployable devices / deployment info (read-only snapshot).
    try:
        dep = await ctx.client.get_all(_base("deployment/deployabledevices", ctx), expanded=True, allow_404=True)
        if dep:
            mapped = [{"name": d.get("name"), "type": d.get("type"), "version": d.get("version")} for d in dep if d.get("name")]
            out["deployment"] = {"deployable_devices": [prune(m) for m in mapped]}
            ctx.count("system.deployment.deployable_devices", len(mapped))
    except Exception as exc:
        ctx.warn(f"system.deployment: {exc}")

    # Smart license (best-effort; avoid exporting sensitive registration tokens).
    try:
        lic = await ctx.client.get(_base("license/smartlicenses", ctx), allow_404=True)
        if lic and isinstance(lic, dict):
            safe = {}
            for k in ["regStatus", "evalExpiresInDays", "evalUsed", "exportControlledFeaturesEnabled"]:
                if lic.get(k) is not None:
                    safe[k] = lic[k]
            if safe:
                out["smart_license"] = safe
                ctx.count("system.smart_license", 1)
    except Exception as exc:
        ctx.warn(f"system.smart_license: {exc}")

    return out
