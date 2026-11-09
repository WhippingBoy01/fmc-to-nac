"""Export FMC policies to NaC YAML."""

from __future__ import annotations

import logging
from typing import Any

from ..nac import prune, ref_name, ref_names
from .base import ExportContext

log = logging.getLogger(__name__)


async def export_policies(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    handlers = [
        ("access_control_policies", _export_access_control),
        ("prefilter_policies", _export_prefilter),
        ("ftd_nat_policies", _export_nat),
        ("file_policies", _export_file),
        ("intrusion_policies", _export_intrusion),
        ("network_analysis_policies", _export_simple_policies, "policy/networkanalysispolicies"),
        ("health_policies", _export_simple_policies, "policy/healthpolicies"),
    ]
    for entry in handlers:
        key = entry[0]
        full_key = f"policies.{key}"
        if ctx.is_excluded(full_key):
            ctx.skip(full_key)
            continue
        fn = entry[1]
        try:
            if fn is _export_simple_policies:
                items = await fn(ctx, entry[2])
            else:
                items = await fn(ctx)
            if items:
                out[key] = items
                ctx.count(full_key, len(items))
        except Exception as exc:
            ctx.warn(f"{full_key}: {exc}")
    return out


def _base(path: str, ctx: ExportContext) -> str:
    return f"/api/fmc_config/v1/domain/{ctx.domain_uuid}/{path.lstrip('/')}"


async def _export_access_control(ctx: ExportContext) -> list[dict[str, Any]]:
    policies = await ctx.client.get_all(_base("policy/accesspolicies", ctx), expanded=True, allow_404=True)
    result = []
    for pol in policies:
        pid = pol.get("id")
        item: dict[str, Any] = {"name": pol.get("name")}
        for k in ["description", "defaultAction"]:
            pass
        if pol.get("description"):
            item["description"] = pol["description"]
        da = pol.get("defaultAction") or {}
        if isinstance(da, dict):
            if da.get("action"):
                item["default_action"] = da["action"]
            for fk, nk in [
                ("intrusionPolicy", "base_intrusion_policy"),
                ("variableSet", "base_variable_set"),
                ("logBegin", "log_connection_begin"),
                ("logEnd", "log_connection_end"),
                ("sendEventsToFMC", "send_events_to_fmc"),
                ("enableSyslog", "send_syslog"),
                ("syslogSeverity", "syslog_severity"),
                ("syslogConfig", "syslog_alert"),
                ("snmpConfig", "snmp_alert"),
            ]:
                v = da.get(fk)
                if v is None:
                    continue
                item[nk] = ref_name(v) if isinstance(v, dict) and fk in {"intrusionPolicy", "variableSet", "syslogConfig", "snmpConfig"} else v
        if pol.get("prefilterPolicySetting"):
            name = ref_name(pol["prefilterPolicySetting"])
            if name:
                item["prefilter_policy"] = name
        if pid:
            try:
                cats = await ctx.client.get_all(_base(f"policy/accesspolicies/{pid}/categories", ctx), allow_404=True)
                cat_items = []
                for c in cats:
                    if c.get("name"):
                        ci = {"name": c["name"]}
                        # metadata section info is not always present; best-effort.
                        cat_items.append(ci)
                if cat_items:
                    item["categories"] = cat_items
            except Exception as exc:
                ctx.warn(f"policies.access_control_policies[{item.get('name')}].categories: {exc}")
            try:
                rules = await ctx.client.get_all(_base(f"policy/accesspolicies/{pid}/accessrules", ctx), expanded=True, allow_404=True)
                mapped_rules = [_map_access_rule(r) for r in rules]
                mapped_rules = [r for r in mapped_rules if r]
                if mapped_rules:
                    item["access_rules"] = mapped_rules
            except Exception as exc:
                ctx.warn(f"policies.access_control_policies[{item.get('name')}].access_rules: {exc}")
        result.append(prune(item))
    return result


def _map_access_rule(rule: dict[str, Any]) -> dict[str, Any] | None:
    name = rule.get("name")
    if not name:
        return None
    out: dict[str, Any] = {"name": name}
    if rule.get("action"):
        out["action"] = rule["action"]
    if rule.get("enabled") is not None:
        out["enabled"] = rule["enabled"]
    if rule.get("category"):
        out["category"] = rule["category"]
    if rule.get("section"):
        out["section"] = rule["section"]
    for fk, nk in [
        ("sendEventsToFMC", "send_events_to_fmc"),
        ("enableSyslog", "send_syslog"),
        ("logBegin", "log_connection_begin"),
        ("logEnd", "log_connection_end"),
        ("logFiles", "log_files"),
        ("syslogSeverity", "syslog_severity"),
    ]:
        if rule.get(fk) is not None:
            out[nk] = rule[fk]
    for fk, nk in [
        ("variableSet", "variable_set"),
        ("intrusionPolicy", "intrusion_policy"),
        ("filePolicy", "file_policy"),
        ("timeRange", "time_range"),
        ("snmpConfig", "snmp_alert"),
        ("syslogConfig", "syslog_alert"),
    ]:
        v = rule.get(fk)
        if isinstance(v, dict) and v.get("name"):
            out[nk] = v["name"]
    # Networks/zones/ports/urls/apps/geolocation/sgt/dynamic/vlan.
    nets = rule.get("sourceNetworks") or {}
    if nets.get("objects"):
        out["source_network_objects"] = ref_names(nets["objects"])
    if nets.get("literals"):
        out["source_network_literals"] = [_lit_value(x) for x in nets["literals"] if _lit_value(x)]
    dnets = rule.get("destinationNetworks") or {}
    if dnets.get("objects"):
        out["destination_network_objects"] = ref_names(dnets["objects"])
    if dnets.get("literals"):
        out["destination_network_literals"] = [_lit_value(x) for x in dnets["literals"] if _lit_value(x)]
    if rule.get("sourceZones", {}).get("objects"):
        out["source_zones"] = ref_names(rule["sourceZones"]["objects"])
    if rule.get("destinationZones", {}).get("objects"):
        out["destination_zones"] = ref_names(rule["destinationZones"]["objects"])
    sp = rule.get("sourcePorts") or {}
    if sp.get("objects"):
        out["source_port_objects"] = ref_names(sp["objects"])
    if sp.get("literals"):
        out["source_port_literals"] = [prune(x, strip_keys={"type"}) for x in sp["literals"]]
    dp = rule.get("destinationPorts") or {}
    if dp.get("objects"):
        out["destination_port_objects"] = ref_names(dp["objects"])
    if dp.get("literals"):
        out["destination_port_literals"] = [prune(x, strip_keys={"type"}) for x in dp["literals"]]
    urls = rule.get("urls") or {}
    if urls.get("objects"):
        out["url_objects"] = ref_names(urls["objects"])
    if urls.get("literals"):
        out["url_literals"] = [x.get("url") for x in urls["literals"] if isinstance(x, dict) and x.get("url")]
    apps = rule.get("applications") or {}
    if apps.get("applications"):
        out["applications"] = [a.get("name") for a in apps["applications"] if a.get("name")]
    if apps.get("applicationFilters"):
        out["application_filter_objects"] = ref_names(apps["applicationFilters"])
    src_dyn = rule.get("sourceDynamicObjects") or {}
    if src_dyn.get("objects"):
        out["source_dynamic_objects"] = ref_names(src_dyn["objects"])
    dst_dyn = rule.get("destinationDynamicObjects") or {}
    if dst_dyn.get("objects"):
        out["destination_dynamic_objects"] = ref_names(dst_dyn["objects"])
    src_sgt = rule.get("sourceSecurityGroupTags") or {}
    if src_sgt.get("objects"):
        out["source_sgts"] = ref_names(src_sgt["objects"])
    dst_sgt = rule.get("destinationSecurityGroupTags") or {}
    if dst_sgt.get("objects"):
        out["destination_sgts"] = ref_names(dst_sgt["objects"])
    if rule.get("vlanTags", {}).get("objects"):
        out["vlan_tag_objects"] = ref_names(rule["vlanTags"]["objects"])
    if rule.get("vlanTags", {}).get("literals"):
        lits = []
        for lit in rule["vlanTags"]["literals"]:
            if isinstance(lit, dict):
                ml = {}
                if lit.get("startTag") is not None:
                    ml["start_tag"] = lit["startTag"]
                if lit.get("endTag") is not None:
                    ml["end_tag"] = lit["endTag"]
                if ml:
                    lits.append(ml)
        if lits:
            out["vlan_tag_literals"] = lits
    return prune(out)


def _lit_value(x: Any) -> str | None:
    if isinstance(x, dict):
        return x.get("value") or x.get("url")
    if isinstance(x, str):
        return x
    return None


async def _export_prefilter(ctx: ExportContext) -> list[dict[str, Any]]:
    policies = await ctx.client.get_all(_base("policy/prefilterpolicies", ctx), expanded=True, allow_404=True)
    result = []
    for pol in policies:
        pid = pol.get("id")
        item = {"name": pol.get("name")}
        if pol.get("description"):
            item["description"] = pol["description"]
        da = pol.get("defaultAction") or {}
        if isinstance(da, dict) and da.get("action"):
            item["default_action"] = da["action"]
        if pid:
            for rules_key, endpoint in [("prefilter_rules", "prefilterrules"), ("tunnel_rules", "tunnelrules")]:
                try:
                    rules = await ctx.client.get_all(_base(f"policy/prefilterpolicies/{pid}/{endpoint}", ctx), expanded=True, allow_404=True)
                    if rules:
                        item[rules_key] = [prune(_generic_rule(r)) for r in rules if r.get("name")]
                except Exception as exc:
                    ctx.warn(f"policies.prefilter_policies[{item['name']}].{rules_key}: {exc}")
        result.append(prune(item))
    return result


async def _export_nat(ctx: ExportContext) -> list[dict[str, Any]]:
    policies = await ctx.client.get_all(_base("policy/ftdnatpolicies", ctx), expanded=True, allow_404=True)
    result = []
    for pol in policies:
        pid = pol.get("id")
        item = {"name": pol.get("name")}
        if pol.get("description"):
            item["description"] = pol["description"]
        if pid:
            all_rules = []
            for endpoint in ["autonatrules", "manualnatrules", "natrules"]:
                try:
                    rules = await ctx.client.get_all(_base(f"policy/ftdnatpolicies/{pid}/{endpoint}", ctx), expanded=True, allow_404=True)
                    for r in rules:
                        mr = _map_nat_rule(r)
                        if endpoint == "autonatrules" and "nat_type" not in mr:
                            mr["nat_type"] = "AUTO"
                        if endpoint == "manualnatrules" and "nat_type" not in mr:
                            mr["nat_type"] = "MANUAL"
                        if mr:
                            all_rules.append(mr)
                except Exception:
                    # Different FMC versions expose different rule endpoints.
                    pass
            # Deduplicate by (name, type) best-effort.
            if all_rules:
                item["nat_rules"] = all_rules
        result.append(prune(item))
    return result


def _map_nat_rule(rule: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if rule.get("name"):
        out["name"] = rule["name"]
    if rule.get("description"):
        out["description"] = rule["description"]
    if rule.get("enabled") is not None:
        out["enabled"] = rule["enabled"]
    if rule.get("natType"):
        out["nat_type"] = rule["natType"]
    if rule.get("type") == "FTDAutoNatRule":
        out.setdefault("nat_type", "AUTO")
    if rule.get("type") == "FTDManualNatRule":
        out.setdefault("nat_type", "MANUAL")
    if rule.get("section"):
        out["section"] = rule["section"]
    for fk, nk in [
        ("sourceInterface", "source_interface"),
        ("destinationInterface", "destination_interface"),
        ("originalSource", "original_source"),
        ("originalDestination", "original_destination"),
        ("translatedSource", "translated_source"),
        ("translatedDestination", "translated_destination"),
        ("originalSourcePort", "original_source_port"),
        ("originalDestinationPort", "original_destination_port"),
        ("translatedSourcePort", "translated_source_port"),
        ("translatedDestinationPort", "translated_destination_port"),
    ]:
        v = rule.get(fk)
        if isinstance(v, dict) and v.get("name"):
            out[nk] = v["name"]
        elif v is not None and not isinstance(v, dict):
            out[nk] = v
    if rule.get("interfaceInTranslatedSource") is not None:
        out["interface_in_translated_source"] = rule["interfaceInTranslatedSource"]
    if rule.get("interfaceInOriginalDestination") is not None:
        out["interface_in_original_destination"] = rule["interfaceInOriginalDestination"]
    if rule.get("fallThrough") is not None:
        out["fall_through"] = rule["fallThrough"]
    if rule.get("dns") is not None:
        out["dns"] = rule["dns"]
    if rule.get("routeLookup") is not None:
        out["route_lookup"] = rule["routeLookup"]
    if rule.get("noProxyArp") is not None:
        out["no_proxy_arp"] = rule["noProxyArp"]
    if rule.get("netToNet") is not None:
        out["net_to_net"] = rule["netToNet"]
    if rule.get("sourceInterface") and isinstance(rule["sourceInterface"], dict) and rule["sourceInterface"].get("name"):
        out["source_interface"] = rule["sourceInterface"]["name"]
    if rule.get("destinationInterface") and isinstance(rule["destinationInterface"], dict) and rule["destinationInterface"].get("name"):
        out["destination_interface"] = rule["destinationInterface"]["name"]
    # NaC NAT schema varies; keep useful extra fields best-effort.
    for k in ["patOptions", "unidirectional"]:
        if rule.get(k) is not None:
            out[k] = prune(rule[k], strip_keys={"id", "links", "metadata", "version"})
    return prune(out)


async def _export_file(ctx: ExportContext) -> list[dict[str, Any]]:
    policies = await ctx.client.get_all(_base("policy/filepolicies", ctx), expanded=True, allow_404=True)
    result = []
    for pol in policies:
        item = {"name": pol.get("name")}
        if pol.get("description"):
            item["description"] = pol["description"]
        pid = pol.get("id")
        if pid:
            try:
                rules = await ctx.client.get_all(_base(f"policy/filepolicies/{pid}/filerules", ctx), expanded=True, allow_404=True)
                if rules:
                    mapped = []
                    for r in rules:
                        mr = {"action": r.get("action")}
                        if r.get("applicationProtocol"):
                            mr["application_protocol"] = r["applicationProtocol"]
                        if r.get("directionOfTransfer"):
                            mr["direction_of_transfer"] = r["directionOfTransfer"]
                        if r.get("fileCategories"):
                            mr["file_categories"] = ref_names(r["fileCategories"])
                        if r.get("fileTypes"):
                            mr["file_types"] = ref_names(r["fileTypes"])
                        mapped.append(prune(mr))
                    item["file_rules"] = mapped
            except Exception as exc:
                ctx.warn(f"policies.file_policies[{item['name']}].file_rules: {exc}")
        result.append(prune(item))
    return result


async def _export_intrusion(ctx: ExportContext) -> list[dict[str, Any]]:
    policies = await ctx.client.get_all(_base("policy/intrusionpolicies", ctx), expanded=True, allow_404=True)
    result = []
    for pol in policies:
        item = {"name": pol.get("name")}
        if pol.get("description"):
            item["description"] = pol["description"]
        if pol.get("inspectionMode"):
            item["inspection_mode"] = pol["inspectionMode"]
        base = pol.get("basePolicy")
        if isinstance(base, dict) and base.get("name"):
            item["base_policy"] = base["name"]
        result.append(prune(item))
    return result


async def _export_simple_policies(ctx: ExportContext, suffix: str) -> list[dict[str, Any]]:
    items = await ctx.client.get_all(_base(suffix, ctx), expanded=True, allow_404=True)
    result = []
    for pol in items:
        if pol.get("name"):
            item = {"name": pol["name"]}
            if pol.get("description"):
                item["description"] = pol["description"]
            if pol.get("defaultAction"):
                item["default_action"] = pol["defaultAction"]
            result.append(prune(item))
    return result


def _generic_rule(rule: dict[str, Any]) -> dict[str, Any]:
    out = {"name": rule.get("name")}
    for k in ["action", "enabled", "description", "ruleType", "bidirectional", "syslogSeverity"]:
        if rule.get(k) is not None:
            nk = {"ruleType": "rule_type", "syslogSeverity": "syslog_severity"}.get(k, k)
            out[nk] = rule[k]
    for fk, nk in [
        ("sourceInterfaces", "source_interfaces"),
        ("destinationInterfaces", "destination_interfaces"),
        ("sourceNetworks", "source_networks"),
        ("destinationNetworks", "destination_networks"),
        ("sourcePorts", "source_ports"),
        ("destinationPorts", "destination_ports"),
        ("encapsulationPorts", "encapsulation_ports"),
    ]:
        v = rule.get(fk)
        if isinstance(v, dict):
            mapped = {}
            if v.get("objects"):
                mapped["objects"] = ref_names(v["objects"])
            if v.get("literals"):
                mapped["literals"] = [prune(x, strip_keys={"id", "type"}) for x in v["literals"]]
            if mapped:
                out[nk] = mapped
        elif isinstance(v, list):
            out[nk] = ref_names(v)
    return out
