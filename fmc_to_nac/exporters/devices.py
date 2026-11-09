"""Export FMC devices to NaC YAML (best-effort)."""

from __future__ import annotations

import logging
from typing import Any

from ..nac import prune, ref_name, ref_names
from .base import ExportContext

log = logging.getLogger(__name__)


def _base(suffix: str, ctx: ExportContext) -> str:
    return f"/api/fmc_config/v1/domain/{ctx.domain_uuid}/{suffix.lstrip('/')}"


async def export_devices(ctx: ExportContext) -> dict[str, Any]:
    out: dict[str, Any] = {}
    # (nac_key, exporter_fn, api_endpoint_suffix_or_None)
    specs = [
        ("devices", _export_device_records, None),
        ("ha_pairs", _export_simple_devices, "devicehapairs"),
        ("clusters", _export_simple_devices, "deviceclusters"),
        ("chassis", _export_chassis, None),
        ("ftd_platform_settings", _export_simple_devices, "policy/ftdplatformsettingspolicies"),
    ]
    for nac_key, fn, endpoint in specs:
        try:
            if endpoint is not None:
                items = await fn(ctx, nac_key, endpoint)
            else:
                items = await fn(ctx)
            if items:
                out[nac_key] = items
                ctx.count(f"devices.{nac_key}", len(items))
        except Exception as exc:
            ctx.warn(f"devices.{nac_key}: {exc}")
    return out


async def _export_device_records(ctx: ExportContext) -> list[dict[str, Any]]:
    devices = await ctx.client.get_all(_base("devices/devicerecords", ctx), expanded=True, allow_404=True)
    result = []
    for dev in devices:
        item: dict[str, Any] = {"name": dev.get("name")}
        for fk, nk in [
            ("hostName", "host"),
            ("regKey", "registration_key"),
            ("natID", "nat_id"),
            ("license_caps", "licenses"),
            ("performanceTier", "performance_tier"),
        ]:
            if dev.get(fk) is not None:
                item[nk] = dev[fk]
        acp = dev.get("accessPolicy")
        if isinstance(acp, dict) and acp.get("name"):
            item["access_control_policy"] = acp["name"]
        nat = dev.get("natPolicy")
        if isinstance(nat, dict) and nat.get("name"):
            item["nat_policy"] = nat["name"]
        health = dev.get("healthPolicy")
        if isinstance(health, dict) and health.get("name"):
            item["health_policy"] = health["name"]
        pft = dev.get("platformSettings")
        if isinstance(pft, dict) and pft.get("name"):
            item["platform_settings_policy"] = pft["name"]
        did = dev.get("id")
        if did:
            item["vrfs"] = await _export_vrfs(ctx, did)
        result.append(prune(item))
    return result


async def _export_vrfs(ctx: ExportContext, device_id: str) -> list[dict[str, Any]]:
    try:
        vrfs = await ctx.client.get_all(_base(f"devices/devicerecords/{device_id}/routing/virtualrouters", ctx), expanded=True, allow_404=True)
    except Exception as exc:
        ctx.warn(f"devices.vrfs[{device_id}]: {exc}")
        return []
    out = []
    for vrf in vrfs:
        v: dict[str, Any] = {"name": vrf.get("name", "Global")}
        vid = vrf.get("id")
        if vid:
            for nk, ep, mapper in [
                ("physical_interfaces", f"devices/devicerecords/{device_id}/routing/virtualrouters/{vid}/physicalinterfaces", _map_interface),
                ("sub_interfaces", f"devices/devicerecords/{device_id}/routing/virtualrouters/{vid}/subinterfaces", _map_interface),
                ("etherchannel_interfaces", f"devices/devicerecords/{device_id}/routing/virtualrouters/{vid}/etherchannelinterfaces", _map_interface),
                ("loopback_interfaces", f"devices/devicerecords/{device_id}/routing/virtualrouters/{vid}/loopbackinterfaces", _map_loopback),
                ("virtual_tunnel_interfaces", f"devices/devicerecords/{device_id}/routing/virtualrouters/{vid}/virtualtunnelinterfaces", _map_interface),
                ("ipv4_static_routes", f"devices/devicerecords/{device_id}/routing/virtualrouters/{vid}/ipv4staticroutes", _map_ipv4_static_route),
                ("ipv6_static_routes", f"devices/devicerecords/{device_id}/routing/virtualrouters/{vid}/ipv6staticroutes", _map_ipv6_static_route),
            ]:
                try:
                    items = await ctx.client.get_all(_base(ep, ctx), expanded=True, allow_404=True)
                    mapped = [x for it in items if (x := mapper(it))]
                    if mapped:
                        v[nk] = mapped
                except Exception:
                    pass
            try:
                bgp = await ctx.client.get(_base(f"devices/devicerecords/{device_id}/routing/virtualrouters/{vid}/bgp", ctx), allow_404=True)
                if bgp and isinstance(bgp, dict):
                    mb = _map_bgp(bgp)
                    if mb:
                        v["bgp"] = mb
            except Exception:
                pass
        out.append(prune(v))
    return out or [{"name": "Global"}]


def _map_interface(item: dict[str, Any]) -> dict[str, Any] | None:
    name = item.get("name") or item.get("ifname")
    if not name and not item.get("id"):
        return None
    out: dict[str, Any] = {}
    if item.get("ifname"):
        out["name"] = item["ifname"] if item.get("subIntfId") or item.get("vlanId") else item.get("name", item["ifname"])
        out["logical_name"] = item["ifname"]
    if item.get("name") and "name" not in out:
        out["name"] = item["name"]
    if item.get("description"):
        out["description"] = item["description"]
    if item.get("enabled") is not None:
        out["enabled"] = item["enabled"]
    if item.get("managementOnly") is not None:
        out["management_only"] = item["managementOnly"]
    if item.get("MTU") is not None:
        out["mtu"] = item["MTU"]
    if item.get("mode"):
        out["mode"] = item["mode"]
    sz = item.get("securityZone")
    if isinstance(sz, dict) and sz.get("name"):
        out["security_zone"] = sz["name"]
    ipv4 = item.get("ipv4") or {}
    if isinstance(ipv4, dict):
        static = ipv4.get("static") or {}
        if isinstance(static, dict):
            if static.get("address"):
                out["ipv4_static_address"] = static["address"]
            if static.get("netmask"):
                out["ipv4_static_netmask"] = static["netmask"]
        dhcp = ipv4.get("dhcp") or {}
        if isinstance(dhcp, dict) and dhcp.get("enableDefaultRouteDHCP") is not None:
            out["ipv4_dhcp_obtain_route"] = dhcp["enableDefaultRouteDHCP"]
    if item.get("vlanId") is not None:
        out["vlan_id"] = item["vlanId"]
    if item.get("subIntfId") is not None:
        out["sub_interface_id"] = item["subIntfId"]
    return prune(out) or None


def _map_loopback(item: dict[str, Any]) -> dict[str, Any] | None:
    out = _map_interface(item) or {}
    if item.get("loopbackId") is not None:
        out.setdefault("name", f"Loopback{item['loopbackId']}")
        out["loopback_id"] = item["loopbackId"]
    return prune(out) or None


def _map_ipv4_static_route(item: dict[str, Any]) -> dict[str, Any] | None:
    out: dict[str, Any] = {}
    nets = item.get("selectedNetworks") or []
    names = ref_names(nets)
    if names:
        out["name"] = names[0] if len(names) == 1 else ",".join(names)
        out["selected_networks"] = names
    if item.get("metricValue") is not None:
        out["metric_value"] = item["metricValue"]
    gw = item.get("gateway") or {}
    if isinstance(gw, dict):
        if gw.get("object"):
            out["gateway"] = {"object": ref_name(gw["object"])}
        elif gw.get("literal"):
            out["gateway"] = {"literal": gw["literal"] if isinstance(gw["literal"], str) else gw["literal"].get("value")}
    iface = item.get("interfaceName") or item.get("routeTracking")
    if isinstance(item.get("interfaceName"), str):
        out["interface_logical_name"] = item["interfaceName"]
    return prune(out) or None


def _map_ipv6_static_route(item: dict[str, Any]) -> dict[str, Any] | None:
    out = _map_ipv4_static_route(item) or {}
    return out or None


def _map_bgp(bgp: dict[str, Any]) -> dict[str, Any] | None:
    out: dict[str, Any] = {}
    gs = bgp.get("generalSettings") or bgp.get("asNumber")
    if isinstance(gs, dict):
        if gs.get("asNumber"):
            out["as_number"] = gs["asNumber"]
    if bgp.get("asNumber") and "as_number" not in out:
        out["as_number"] = bgp["asNumber"]
    return prune(out) or None


async def _export_simple_devices(ctx: ExportContext, key: str, endpoint: str) -> list[dict[str, Any]]:
    items = await ctx.client.get_all(_base(endpoint, ctx), expanded=True, allow_404=True)
    out = []
    for item in items:
        if item.get("name"):
            o = {"name": item["name"]}
            if item.get("description"):
                o["description"] = item["description"]
            out.append(prune(o))
    return out


async def _export_chassis(ctx: ExportContext) -> list[dict[str, Any]]:
    items = await ctx.client.get_all(_base("chassis/fmcmanagedchassis", ctx), expanded=True, allow_404=True)
    out = []
    for item in items:
        if not item.get("name") and not item.get("hostName"):
            continue
        o = {"name": item.get("name") or item.get("hostName")}
        if item.get("hostName"):
            o["host"] = item["hostName"]
        out.append(prune(o))
    return out
