"""Orchestrates FMC export to NaC YAML."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from .config import Settings
from .exporters.base import ExportContext
from .exporters.devices import export_devices
from .exporters.objects import export_objects
from .exporters.policies import export_policies
from .exporters.system import export_system
from .exporters.vpns_integrations import export_integrations, export_vpns
from .fmc_client import FMCClient
from .nac import redact

log = logging.getLogger(__name__)


def _yaml_dump(data: Any) -> str:
    return yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=120,
    )


async def export_fmc(
    settings: Settings,
    *,
    domain_names: list[str] | None = None,
    only: set[str] | None = None,
    exclude: set[str] | None = None,
    redact_sensitive: bool = False,
) -> dict[str, Any]:
    async with FMCClient(
        settings.base_url,
        settings.username,
        settings.password,
        verify=settings.verify,
        timeout=settings.timeout,
        domain_uuid=settings.domain_uuid,
    ) as client:
        await client.login()
        domains = await client.get_all_domains()
        if domain_names:
            wanted = {n.lower() for n in domain_names}
            domains = [d for d in domains if (d.get("name") or "").lower() in wanted]
        if not domains and settings.domain_uuid:
            domains = [{"name": "Global", "uuid": settings.domain_uuid}]

        model: dict[str, Any] = {"fmc": {"domains": []}}
        all_warnings: list[str] = []
        all_counts: dict[str, int] = {}
        all_skipped: dict[str, int] = {}

        for dom in domains:
            duuid = dom.get("uuid")
            dname = dom.get("name") or "Global"
            if not duuid:
                all_warnings.append(f"domain {dname}: missing UUID, skipped")
                continue
            ctx = ExportContext(client=client, domain_uuid=duuid, domain_name=dname, exclude=set(exclude or set()))
            dmodel: dict[str, Any] = {"name": dname}
            steps = [
                ("objects", export_objects, "objects"),
                ("policies", export_policies, "policies"),
                ("devices", export_devices, "devices"),
                ("vpns", export_vpns, "vpns"),
                ("integrations", export_integrations, "integrations"),
            ]
            for key, fn, target in steps:
                full_key = key
                if only and key not in only:
                    continue
                if ctx.is_excluded(full_key):
                    ctx.skip(full_key)
                    continue
                log.info("Exporting %s for domain %s", key, dname)
                try:
                    data = await fn(ctx)
                    if data:
                        dmodel[target] = data
                except Exception as exc:
                    ctx.warn(f"{dname}.{key}: {exc}")

            # System is often modeled globally; attach best-effort under fmc.system as well as per-domain note.
            if not only or "system" in only:
                if not ctx.is_excluded("system"):
                    log.info("Exporting system for domain %s", dname)
                    try:
                        sys = await export_system(ctx)
                        if sys:
                            model["fmc"].setdefault("system", {}).update(sys)
                    except Exception as exc:
                        ctx.warn(f"{dname}.system: {exc}")
                else:
                    ctx.skip("system")

            model["fmc"]["domains"].append(dmodel)
            all_warnings.extend(ctx.warnings)
            for k, v in ctx.exported.items():
                all_counts[k] = all_counts.get(k, 0) + v
            for k, v in ctx.skipped.items():
                all_skipped[k] = all_skipped.get(k, 0) + v

        if redact_sensitive:
            model = redact(model)

        return {
            "model": model,
            "warnings": all_warnings,
            "counts": all_counts,
            "skipped": all_skipped,
            "domains": [{"name": d.get("name"), "uuid": d.get("uuid")} for d in domains],
        }


def _names_only(value: Any) -> Any:
    """Build NaC existing-style name-only structures (best-effort)."""
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict):
                if "name" in item:
                    entry: dict[str, Any] = {"name": item["name"]}
                    # Preserve a few nested name-only shapes useful for devices/VRFs.
                    if isinstance(item.get("vrfs"), list):
                        entry["vrfs"] = _names_only(item["vrfs"])
                    out.append(entry)
                else:
                    mapped = _names_only(item)
                    if mapped:
                        out.append(mapped)
        return out
    if isinstance(value, dict):
        out_d: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(v, list):
                nv = _names_only(v)
                if nv:
                    out_d[k] = nv
            elif isinstance(v, dict):
                nv = _names_only(v)
                if nv:
                    out_d[k] = nv
        return out_d
    return None


def build_existing_helper(model: dict[str, Any]) -> dict[str, Any]:
    """Generate a name-only `existing` helper document from an exported model."""
    fmc = model.get("fmc", {})
    domains = []
    for dom in fmc.get("domains", []):
        edom: dict[str, Any] = {"name": dom.get("name")}
        for section in ["objects", "policies", "devices", "integrations"]:
            if dom.get(section):
                mapped = _names_only(dom[section])
                if mapped:
                    edom[section] = mapped
        domains.append(edom)
    return {"existing": {"fmc": {"domains": domains}}}


def write_output(
    result: dict[str, Any],
    out_dir: Path,
    *,
    single_file: bool = False,
    emit_existing: bool = False,
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    model = result["model"]
    report = {
        "domains": result.get("domains"),
        "counts": result.get("counts"),
        "skipped": result.get("skipped"),
        "warnings": result.get("warnings"),
    }

    if single_file:
        p = out_dir / "fmc.nac.yaml"
        p.write_text(_yaml_dump(model), encoding="utf-8")
        written.append(p)
    else:
        # Split by domain and major sections for readability.
        fmc = model.get("fmc", {})
        system = fmc.get("system")
        if system:
            p = out_dir / "system.nac.yaml"
            p.write_text(_yaml_dump({"fmc": {"system": system}}), encoding="utf-8")
            written.append(p)
        for dom in fmc.get("domains", []):
            safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in (dom.get("name") or "domain"))
            # Full domain file
            p = out_dir / f"domain_{safe}.nac.yaml"
            p.write_text(_yaml_dump({"fmc": {"domains": [dom]}}), encoding="utf-8")
            written.append(p)
            # Section files
            for section in ["objects", "policies", "devices", "vpns", "integrations"]:
                if dom.get(section):
                    sp = out_dir / safe / f"{section}.nac.yaml"
                    sp.parent.mkdir(parents=True, exist_ok=True)
                    sp.write_text(_yaml_dump({"fmc": {"domains": [{"name": dom["name"], section: dom[section]}]}}), encoding="utf-8")
                    written.append(sp)
        # Combined convenience file (NaC merges YAML dirs/files).
        cp = out_dir / "fmc.nac.yaml"
        cp.write_text(_yaml_dump(model), encoding="utf-8")
        written.append(cp)

    if emit_existing:
        ep = out_dir / "existing.nac.yaml"
        ep.write_text(_yaml_dump(build_existing_helper(model)), encoding="utf-8")
        written.append(ep)

    rp = out_dir / "export-report.yaml"
    rp.write_text(_yaml_dump(report), encoding="utf-8")
    written.append(rp)
    return written
