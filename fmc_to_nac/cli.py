"""CLI for FMC to NaC export."""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from .config import ConfigError, load_settings
from .exporter import export_fmc, write_output


def _split_csv(values: list[str] | None) -> set[str]:
    if not values:
        return set()
    out: set[str] = set()
    for v in values:
        for part in v.split(","):
            part = part.strip()
            if part:
                out.add(part)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fmc-to-nac",
        description="Export Cisco FMC configuration to NetAsCode (NaC) FMC YAML (read-only).",
    )
    parser.add_argument("--env-file", help="Path to .env file with FMC credentials/settings")
    parser.add_argument("--out", default="./output", help="Output directory (default: ./output)")
    parser.add_argument("--single-file", action="store_true", help="Write one combined fmc.nac.yaml instead of split files")
    parser.add_argument("--domain", action="append", dest="domains", help="Export only this FMC domain name (repeatable)")
    parser.add_argument(
        "--only",
        help="Comma-separated sections to export: objects,policies,devices,system,vpns,integrations",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        help=(
            "Exclude exports by path/prefix (repeatable or comma-separated). "
            "Examples: objects.intrusion_rules,objects.applications,policies.health_policies"
        ),
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Redact sensitive-looking values (password/secret/token/community/registration_key/etc.) in output",
    )
    parser.add_argument(
        "--emit-existing",
        action="store_true",
        help="Write existing.nac.yaml (name-only NaC `existing` helper) for exported objects/policies/devices/integrations",
    )
    parser.add_argument("--log-level", help="Override LOG_LEVEL (DEBUG, INFO, WARNING, ERROR)")
    args = parser.parse_args(argv)

    try:
        settings = load_settings(args.env_file)
    except ConfigError as exc:
        parser.error(str(exc))

    level = (args.log_level or settings.log_level).upper()
    logging.basicConfig(level=getattr(logging, level, logging.INFO), format="%(levelname)s %(name)s: %(message)s")

    only = {s.strip().lower() for s in args.only.split(",") if s.strip()} if args.only else None
    exclude = _split_csv(args.exclude)

    try:
        result = asyncio.run(
            export_fmc(
                settings,
                domain_names=args.domains,
                only=only,
                exclude=exclude,
                redact_sensitive=args.redact,
            )
        )
    except Exception as exc:
        logging.getLogger(__name__).error("Export failed: %s", exc, exc_info=level == "DEBUG")
        return 1

    written = write_output(result, Path(args.out), single_file=args.single_file, emit_existing=args.emit_existing)
    counts = result.get("counts") or {}
    skipped = result.get("skipped") or {}
    warnings = result.get("warnings") or []
    print(f"Exported {sum(counts.values())} item(s) across {len(counts)} group(s) to {args.out}")
    for k in sorted(counts):
        print(f"  - {k}: {counts[k]}")
    if skipped:
        print(f"Excluded {sum(skipped.values())} group/request(s): {', '.join(sorted(skipped))}")
    if warnings:
        print(f"Warnings: {len(warnings)} (see export-report.yaml)")
        for w in warnings[:20]:
            print(f"  ! {w}")
        if len(warnings) > 20:
            print(f"  ! ... {len(warnings) - 20} more")
    for p in written:
        print(f"Wrote {p}")
    return 0 if result.get("domains") else 2


if __name__ == "__main__":
    raise SystemExit(main())
