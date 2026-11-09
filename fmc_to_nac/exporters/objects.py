"""Export FMC objects to NaC YAML."""

from __future__ import annotations

import logging
from typing import Any

from ..nac import prune, ref_names
from .base import ExportContext

log = logging.getLogger(__name__)

# (nac_key, api_suffix, kind)
# kind controls light normalization.
OBJECT_ENDPOINTS: list[tuple[str, str, str]] = [
    ("hosts", "object/hosts", "host"),
    ("networks", "object/networks", "network"),
    ("ranges", "object/ranges", "range"),
    ("fqdns", "object/fqdns", "fqdn"),
    ("network_groups", "object/networkgroups", "network_group"),
    ("urls", "object/urls", "url"),
    ("url_groups", "object/urlgroups", "url_group"),
    ("ports", "object/ports", "port"),
    ("port_groups", "object/portobjectgroups", "port_group"),
    ("icmpv4s", "object/icmpv4objects", "icmp"),
    ("icmpv6s", "object/icmpv6objects", "icmp"),
    ("security_zones", "object/securityzones", "security_zone"),
    ("interface_groups", "object/interfacegroups", "interface_group"),
    ("vlan_tags", "object/vlantags", "vlan_tag"),
    ("vlan_tag_groups", "object/vlangrouptags", "vlan_tag_group"),
    ("application_filters", "object/applicationfilters", "application_filter"),
    ("applications", "object/applications", "simple"),
    ("dynamic_objects", "object/dynamicobjects", "dynamic_object"),
    ("sgts", "object/securitygrouptags", "sgt"),
    ("time_ranges", "object/timeranges", "time_range"),
    ("tunnel_zones", "object/tunneltags", "simple"),
    ("geolocations", "object/geolocations", "simple"),
    ("continents", "object/continents", "simple"),
    ("countries", "object/countries", "simple"),
    ("dns_server_groups", "object/dnsservergroups", "dns"),
    ("standard_access_lists", "object/standardaccesslists", "acl"),
    ("extended_access_lists", "object/extendedaccesslists", "acl"),
    ("as_paths", "object/aspathlists", "simple"),
    ("ipv4_prefix_lists", "object/ipv4prefixlists", "simple"),
    ("ipv6_prefix_lists", "object/ipv6prefixlists", "simple"),
    ("standard_community_lists", "object/standardcommunitylists", "simple"),
    ("expanded_community_lists", "object/expandedcommunitylists", "simple"),
    ("extended_community_lists", "object/extendedcommunitylists", "simple"),
    ("route_maps", "object/routemaps", "simple"),
    ("policy_lists", "object/policylists", "simple"),
    ("bfd_templates", "object/bfdtemplates", "simple"),
    ("ikev1_policies", "object/ikev1policies", "simple"),
    ("ikev1_ipsec_proposals", "object/ikev1ipsecproposals", "simple"),
    ("ikev2_policies", "object/ikev2policies", "simple"),
    ("ikev2_ipsec_proposals", "object/ikev2ipsecproposals", "simple"),
    ("certificate_enrollments", "object/certenrollments", "simple"),
    ("certificate_maps", "object/certificatemaps", "simple"),
    ("trusted_certificate_authorities", "object/externalcacertificates", "cert"),
    ("internal_certificate_authorities", "object/internalcas", "cert"),
    ("internal_certificates", "object/internalcertificates", "cert"),
    ("external_certificates", "object/externalcertificates", "cert"),
    ("ipv4_address_pools", "object/ipv4addresspools", "simple"),
    ("ipv6_address_pools", "object/ipv6addresspools", "simple"),
    ("group_policies", "object/grouppolicies", "simple"),
    ("radius_server_groups", "object/radiusservergroups", "simple"),
    ("single_sign_on_servers", "object/ssoservers", "simple"),
    ("secure_client_images", "object/anyconnectpackages", "simple"),
    ("secure_client_profiles", "object/anyconnectprofiles", "simple"),
    ("secure_client_customizations", "object/anyconnectcustomizations", "simple"),
    ("secure_client_custom_attributes", "object/anyconnectcustomattributes", "simple"),
    ("secure_client_external_browser_packages", "object/anyconnectexternalbrowserpackages", "simple"),
    ("resource_profiles", "object/resourceprofiles", "simple"),
    ("service_accesses", "object/serviceaccessobjects", "simple"),
    ("realm_sequences", "object/realmsequences", "simple"),
    ("realm_users", "object/realmusers", "simple"),
    ("realm_user_groups", "object/realmusergroups", "simple"),
    ("variable_sets", "object/variablesets", "variableset"),
    ("file_types", "object/filetypes", "simple"),
    ("file_categories", "object/filecategories", "simple"),
    ("endpoint_device_types", "object/endpoints/devicetypes", "simple"),
    ("intrusion_rules", "object/intrusionrules", "simple"),
    ("sla_monitors", "object/slamonitors", "simple"),
]


async def export_objects(ctx: ExportContext) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for nac_key, suffix, kind in OBJECT_ENDPOINTS:
        full_key = f"objects.{nac_key}"
        if ctx.is_excluded(full_key):
            ctx.skip(full_key)
            continue
        path = f"/api/fmc_config/v1/domain/{ctx.domain_uuid}/{suffix.lstrip('/')}"
        try:
            items = await ctx.client.get_all(path, expanded=True, allow_404=True)
            mapped = [m for item in items if (m := _map_object(item, kind))]
            if mapped:
                result[nac_key] = mapped
                ctx.count(full_key, len(mapped))
        except Exception as exc:
            ctx.warn(f"{full_key}: failed to export from {suffix}: {exc}")
    return result


def _map_object(item: dict[str, Any], kind: str) -> dict[str, Any] | None:
    name = item.get("name")
    if not name:
        return None
    out: dict[str, Any] = {"name": name}
    if item.get("description") is not None:
        out["description"] = item["description"]
    if item.get("overridable") is not None:
        out["overridable"] = item["overridable"]

    if kind == "host":
        if item.get("value") is not None:
            out["ip"] = item["value"]
    elif kind == "network":
        if item.get("value") is not None:
            out["prefix"] = item["value"]
    elif kind == "range":
        if item.get("value") is not None:
            out["ip_range"] = item["value"]
    elif kind == "fqdn":
        if item.get("value") is not None:
            out["value"] = item["value"]
        if item.get("dnsResolution") is not None:
            out["dns_resolution"] = item["dnsResolution"]
    elif kind == "url":
        if item.get("url") is not None:
            out["url"] = item["url"]
    elif kind == "network_group":
        objs = ref_names(item.get("objects"))
        lits = item.get("literals") or []
        if objs:
            out["objects"] = objs
        if isinstance(lits, list) and lits:
            out["literals"] = [prune(x, strip_keys=set()) for x in lits]
    elif kind == "url_group":
        objs = ref_names(item.get("objects"))
        lits = item.get("literals") or []
        if objs:
            out["objects"] = objs
        if isinstance(lits, list) and lits:
            out["literals"] = [prune(x, strip_keys=set()) for x in lits]
    elif kind == "port":
        if item.get("protocol") is not None:
            out["protocol"] = item["protocol"]
        if item.get("port") is not None:
            out["port"] = item["port"]
    elif kind == "port_group":
        objs = ref_names(item.get("objects"))
        if objs:
            out["objects"] = objs
    elif kind == "icmp":
        for src, dst in [("icmpType", "icmp_type"), ("code", "code"), ("type", "icmp_type")]:
            if item.get(src) is not None and dst not in out:
                out[dst] = item[src]
    elif kind == "security_zone":
        if item.get("interfaceMode") is not None:
            out["interface_type"] = item["interfaceMode"]
        if item.get("interfaces"):
            out["interfaces"] = ref_names(item.get("interfaces"))
    elif kind == "interface_group":
        if item.get("interfaceMode") is not None:
            out["interface_type"] = item["interfaceMode"]
        if item.get("interfaces"):
            out["interfaces"] = ref_names(item.get("interfaces"))
    elif kind == "vlan_tag":
        data = item.get("data") or {}
        if isinstance(data, dict):
            if data.get("startTag") is not None:
                out["start_tag"] = data["startTag"]
            if data.get("endTag") is not None:
                out["end_tag"] = data["endTag"]
    elif kind == "vlan_tag_group":
        objs = ref_names(item.get("objects"))
        lits = item.get("literals") or []
        if objs:
            out["objects"] = objs
        if isinstance(lits, list) and lits:
            mapped = []
            for lit in lits:
                if isinstance(lit, dict):
                    ml: dict[str, Any] = {}
                    if lit.get("startTag") is not None:
                        ml["start_tag"] = lit["startTag"]
                    if lit.get("endTag") is not None:
                        ml["end_tag"] = lit["endTag"]
                    if ml:
                        mapped.append(ml)
            if mapped:
                out["literals"] = mapped
    elif kind == "sgt":
        if item.get("tag") is not None:
            out["tag"] = item["tag"]
    elif kind == "dynamic_object":
        if item.get("objectType") is not None:
            out["object_type"] = item["objectType"]
    elif kind == "variableset":
        # NaC uses variable_sets; best-effort keep meaningful fields.
        pass
    else:
        # Simple/best-effort: copy selected scalar-ish fields.
        for k, v in item.items():
            if k in {"name", "description", "overridable", "id", "links", "metadata", "type", "version"}:
                continue
            if isinstance(v, (str, int, float, bool)) or v is None:
                out.setdefault(k, v)
            elif isinstance(v, list) and v and isinstance(v[0], dict) and {"id", "type", "name"} & set(v[0].keys()):
                out.setdefault(k, ref_names(v))
    return prune(out)
