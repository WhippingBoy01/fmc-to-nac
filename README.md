# fmc-to-nac

Export an existing **Cisco Secure Firewall Management Center (FMC)** configuration to **[NetAsCode (NaC) FMC](https://netascode.cisco.com/docs/data_models/fmc/overview/)** YAML (the data model used by the [`netascode/nac-fmc/fmc`](https://registry.terraform.io/modules/netascode/nac-fmc/fmc/latest) Terraform module).

`fmc-to-nac` is a **read-only** Python CLI/Docker tool. It connects to the FMC REST API, discovers domains, and generates best-effort NaC-style YAML (`fmc:` root, `*.nac.yaml`-friendly structure) plus an export report.

> **Important:** FMC REST payloads and the NaC FMC/Terraform provider schemas vary by version. This exporter provides **maximum, best-effort coverage** and mapping; **always review, curate, and validate** generated YAML against your FMC version and target `nac-fmc`/`CiscoDevNet/fmc` provider versions before using it with Terraform.

## Features

- **Read-only export** (API `GET`/auth only). No FMC changes, no deploy, no policy writes.
- **Multi-domain aware** (discovers FMC domains; filter with `--domain`).
- **Multiple instances everywhere the API returns them** (paginated): access control policies and rules, FTD NAT/prefilter/file/intrusion/network analysis/health policies, devices (device records, HA pairs, clusters, chassis, FTD platform settings), security zones, network/host/range/FQDN objects, groups, ports/URLs/ICMP/vlans, and other supported NaC areas.
- **Broad NaC coverage (best-effort)**:
  - `fmc.domains[].objects` — hosts, networks, ranges, FQDNs, network/URL/port/ICMP/interface/vlan/app groups & objects, dynamic objects, SGTs, time ranges, geo, DNS, ACLs, prefix/community/policy/route lists, BFD, IKEv1/v2 + IPsec proposals, cert enrollments/maps/cert objects, address pools, group policies, RADIUS/SSO, Secure Client items, variable sets, file types/categories, endpoint device types, intrusion rules, SLA monitors, etc.
  - `fmc.domains[].policies` — access control (policies/categories/rules with refs mapped), prefilter, FTD NAT (auto/manual/nat rules, best-effort), file (+ rules), intrusion, network analysis, health.
  - `fmc.domains[].devices` — device records with per-device VRF sub-resources where available (interfaces, IPv4/IPv6 static routes, basic BGP), HA pairs, clusters, chassis, FTD platform settings.
  - `fmc.domains[].vpns` — site-to-site and remote access (expanded, best-effort/pruned).
  - `fmc.domains[].integrations` — realms/local realms/external identity sources (best-effort).
  - `fmc.system` — best-effort policy assignments, deployable-device info, smart-license status (avoids obvious secrets/tokens).
- **NaC-friendly normalization**: strips FMC API metadata (`id`, `links`, `metadata`, `version`), removes empty values, and converts FMC references (`{id,type,name}`) to names where practical.
- **Operational controls**: `--only`, `--exclude` (e.g., skip huge bulk sets), `--redact`, `--emit-existing`, split or single-file output.
- **Transparent reporting**: `export-report.yaml` contains discovered domains, per-group counts, skipped groups, and warnings/errors (401/403/404/422, API differences, mapping issues). Exports continue best-effort.

## Safety and handling

- FMC exports can contain sensitive operational data (internal IPs, object names, policy logic, topology). Treat outputs as sensitive.
- **Never commit `.env` files or credentials.** Use read-only/least-privilege FMC API accounts.
- `--redact` masks sensitive-looking keys (`password`, `secret`, `token`, `community`, `registration_key`, etc.) as a helper, **not a guarantee** — review output before sharing.
- FMC changes affect firewall policy. This tool is read-only, but generated NaC/Terraform can make changes if applied later. Validate plans carefully.

## Requirements

- Cisco FMC with REST API access (read permissions for the data you want to export).
- Python 3.10+ (local) or Docker.
- Network access from the runner to `https://<fmc-host>/api/...`.

Find your FMC API Explorer at: `https://<fmc-host>/api/api-explorer/`.

## Quick start (local)

```bash
git clone <your-repo-url> fmc-to-nac
cd fmc-to-nac

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env: FMC_HOST, FMC_USERNAME, FMC_PASSWORD, FMC_VERIFY_SSL/FMC_CA_BUNDLE

python -m fmc_to_nac --env-file .env --out ./output
```

## Quick start (Docker)

```bash
docker build -t fmc-to-nac:local .

cp .env.example .env
# edit .env (or pass env vars explicitly)

mkdir -p output
docker run --rm \
  --env-file .env \
  -v "$(pwd)/output:/out" \
  fmc-to-nac:local --out /out --redact
```

With an explicit CA bundle for a lab/self-signed FMC certificate:

```bash
docker run --rm \
  --env-file .env \
  -e FMC_CA_BUNDLE=/certs/fmc-ca.pem \
  -v "$(pwd)/output:/out" \
  -v "$(pwd)/certs:/certs:ro" \
  fmc-to-nac:local --out /out
```

## Quick start (Docker Compose)

```bash
cp .env.example .env
# edit .env
docker compose run --rm fmc-to-nac --out /out --redact
# or override command:
docker compose run --rm fmc-to-nac --out /out --only objects,policies --exclude objects.intrusion_rules,objects.applications
```

## Configuration

Configuration is loaded from environment variables (optionally via `--env-file` / `.env`). Explicit environment variables are not overridden by a local `.env`.

| Variable | Required | Default | Description |
|---|---:|---|---|
| `FMC_HOST` | yes | - | FMC base URL, e.g. `https://fmc.example.local` |
| `FMC_USERNAME` | yes | - | FMC API username (read-only recommended) |
| `FMC_PASSWORD` | yes | - | FMC API password |
| `FMC_DOMAIN_UUID` | no | auto-discover | FMC domain UUID override |
| `FMC_VERIFY_SSL` | no | `true` | Verify TLS certificate |
| `FMC_CA_BUNDLE` | no | - | Path to CA bundle for private/self-signed FMC certs |
| `FMC_TIMEOUT` | no | `60` | HTTP timeout (seconds) |
| `LOG_LEVEL` | no | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

## CLI reference

```text
python -m fmc_to_nac [options]

  --env-file PATH           Path to .env file
  --out DIR                 Output directory (default: ./output)
  --single-file             Write one combined fmc.nac.yaml instead of split files
  --domain NAME             Export only this FMC domain (repeatable)
  --only SECTIONS           Comma-separated: objects,policies,devices,system,vpns,integrations
  --exclude PATHS           Exclude by path/prefix (repeatable/comma-separated)
                            Examples:
                              objects.intrusion_rules,objects.applications
                              policies.health_policies
                              system
  --redact                  Mask sensitive-looking values in output
  --emit-existing           Write existing.nac.yaml (name-only NaC existing helper)
  --log-level LEVEL         DEBUG|INFO|WARNING|ERROR
```

### Practical examples

```bash
# Full best-effort export
python -m fmc_to_nac --env-file .env --out ./output

# "Everything" but skip very large bulk object sets
python -m fmc_to_nac --env-file .env --out ./output \
  --exclude objects.intrusion_rules,objects.applications

# Focused export for review
python -m fmc_to_nac --env-file .env --out ./output \
  --only objects,policies --domain Global

# Safer shareable artifact + NaC existing helper
python -m fmc_to_nac --env-file .env --out ./output \
  --exclude objects.intrusion_rules,objects.applications \
  --redact --emit-existing

# Troubleshooting API/permissions/mapping
python -m fmc_to_nac --env-file .env --out ./output --log-level DEBUG
```

## Output files

Default (split) output:

```text
output/
  fmc.nac.yaml                 # combined convenience file
  system.nac.yaml              # best-effort global system section (if exported)
  domain_<Domain>.nac.yaml     # full per-domain file
  <Domain>/
    objects.nac.yaml
    policies.nac.yaml
    devices.nac.yaml
    vpns.nac.yaml
    integrations.nac.yaml
  existing.nac.yaml            # only with --emit-existing (name-only helper)
  export-report.yaml           # domains, counts, skipped, warnings
```

`--single-file` writes only `fmc.nac.yaml` (+ `export-report.yaml`, and `existing.nac.yaml` if requested).

## NaC mapping notes and limitations

- **Target format:** NaC FMC data model (`fmc.domains[].objects/policies/devices/vpns/integrations`, plus best-effort `fmc.system`). See [NaC FMC overview](https://netascode.cisco.com/docs/data_models/fmc/overview/) and [features/data models](https://netascode.cisco.com/docs/data_models/fmc/features/).
- **Best-effort by design:** FMC API fields and NaC provider/module schemas differ across versions. The exporter maps common fields, keeps useful expanded/pruned data where safe, and warns on failures.
- **Permissions/features:** 401/403/404/422 responses usually mean the account lacks access, the feature isn’t licensed/enabled, or the endpoint differs on that FMC version. These are reported, not fatal for the whole export.
- **Domains:** FMC domains are discovered; FMC API domain creation is a GUI concern (NaC caveat). Exported names are for modeling.
- **Devices/VRFs/interfaces/routes/BGP/VPNs:** deeply nested and version-sensitive. Exported as best-effort; validate carefully before planning/apply.
- **`existing` helper:** `--emit-existing` produces name-only candidates. It does not decide what should be managed vs. pre-existing. Curate it (e.g., keep `any-ipv4`, built-in ports/policies you don’t manage) per NaC guidance: [Using existing objects](https://netascode.cisco.com/docs/guides/fmc/using_existing_objects/).
- **Not a Terraform state importer:** this tool generates NaC YAML input data. Integrating with an existing `nac-fmc` Terraform deployment may require state/import planning.

## Validate with NetAsCode (recommended)

After reviewing and curating the output, validate in a NaC FMC/Terraform workspace that targets the correct module/provider versions:

```bash
# example workflow (adapt to your nac-fmc setup)
terraform init
terraform validate
terraform plan
```

Use a non-production FMC/lab or a carefully reviewed plan before any apply. Confirm write payload expectations in FMC API Explorer for your FMC version.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m py_compile fmc_to_nac/*.py fmc_to_nac/exporters/*.py
pytest -q
```

Project layout:

```text
fmc_to_nac/
  cli.py                 # CLI entrypoint
  config.py              # env/.env settings
  fmc_client.py          # async FMC REST client (read-only)
  nac.py                 # NaC helpers (prune/redact/refs)
  exporter.py            # orchestration + output/report/existing helper
  exporters/
    base.py              # export context, exclude/skip/count/warn
    objects.py           # object endpoints + mappings
    policies.py          # ACP/prefilter/NAT/file/intrusion/analysis/health
    devices.py           # devices/HA/cluster/chassis/platform settings + subresources
    system.py            # system (best-effort)
    vpns_integrations.py # VPNs and integrations (best-effort)
```

## Troubleshooting

- **Auth fails (401 on token generation):** check `FMC_HOST`, credentials, and FMC API reachability. Use a dedicated read-only API user.
- **TLS errors:** keep verification enabled; provide `FMC_CA_BUNDLE` for private CAs/self-signed lab certs.
- **403/404/422 warnings:** often permissions, disabled features, licensing, or FMC-version endpoint differences. Inspect `export-report.yaml` and run with `--log-level DEBUG`.
- **Large exports:** use `--exclude objects.intrusion_rules,objects.applications` (and/or other bulk groups) for faster, smaller runs.
- **NaC plan shows unexpected diffs:** expected on first adoption; NaC keys/defaults may not exactly match FMC’s internal representation. Curate generated YAML, use `existing` for unmanaged/predefined objects, and validate incrementally.

## License

This project is provided under the MIT License (see `LICENSE`). Review and set the appropriate license/copyright for your organization before publishing publicly.
