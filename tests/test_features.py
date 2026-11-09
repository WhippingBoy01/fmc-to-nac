from fmc_to_nac.exporters.base import ExportContext
from fmc_to_nac.exporter import build_existing_helper
from fmc_to_nac.nac import redact


class _Dummy:
    pass


def test_exclude_paths():
    ctx = ExportContext(client=_Dummy(), domain_uuid="x", domain_name="Global", exclude={"objects.intrusion_rules", "system"})
    assert ctx.is_excluded("objects.intrusion_rules")
    assert not ctx.is_excluded("objects.hosts")
    assert ctx.is_excluded("system")


def test_redact_sensitive_keys():
    data = {"name": "x", "registration_key": "secret", "nested": {"password": "pw", "ok": 1}}
    out = redact(data)
    assert out["registration_key"] == "<REDACTED>"
    assert out["nested"]["password"] == "<REDACTED>"
    assert out["nested"]["ok"] == 1


def test_existing_helper_names_only():
    model = {
        "fmc": {
            "domains": [
                {
                    "name": "Global",
                    "objects": {"hosts": [{"name": "h1", "ip": "1.2.3.4"}]},
                    "policies": {"access_control_policies": [{"name": "acp1", "default_action": "BLOCK"}]},
                }
            ]
        }
    }
    ex = build_existing_helper(model)
    assert ex["existing"]["fmc"]["domains"][0]["objects"]["hosts"] == [{"name": "h1"}]
    assert ex["existing"]["fmc"]["domains"][0]["policies"]["access_control_policies"] == [{"name": "acp1"}]
