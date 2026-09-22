#!/usr/bin/env python3
"""
Verify the deployment configuration rather than asserting it.

Two checks, because two different things are being claimed:

``app-layer``
    Runs Suricata over the committed write capture twice — with the Modbus
    application-layer parser disabled and enabled — and records what happens.
    This is the load-bearing claim in the sensor configuration: without the
    parser the OT rules never fire, so a sensor that is missing this setting
    looks healthy and detects nothing.

``malcolm-config``
    Reads the ``SURICATA_*`` variables the fragments set and checks them against
    Malcolm's own config generator: that each variable is one the generator
    reads, and that the variables gating Modbus/DNP3 parsing and EVE output are
    present. This is static by necessity — proving it against a running Malcolm
    means running Malcolm, which is an operator step in deployment/README.md.

Evidence is written to ``deployment/evidence/`` and guarded by tests, so a
fragment edited without re-running this fails the suite.

Usage:
    python deployment/verify_deployment.py --malcolm ../Malcolm
    python deployment/verify_deployment.py            # both checks
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = REPO_ROOT / "deployment"
EVIDENCE = DEPLOYMENT / "evidence"
FRAGMENTS = {
    "suricata.env.fragment": DEPLOYMENT / "malcolm" / "config" / "suricata.env.fragment",
    "pcap-capture.env.fragment": DEPLOYMENT / "malcolm" / "config" / "pcap-capture.env.fragment",
}
DEFAULT_MALCOLM = REPO_ROOT.parent / "Malcolm"
DEFAULT_IMAGE = "jasonish/suricata:latest"
DEFAULT_RULES = (
    REPO_ROOT.parent / "ot-detection-engineering" / "deploy" / "suricata" / "ot-detection.rules"
)
CAPTURE = REPO_ROOT / "pcaps" / "setpoint_write.pcap"
EXPECTED_SID = 9000001


def sha256(path: Path) -> str:
    """Return the SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            digest.update(block)
    return digest.hexdigest()


def fragment_variables(path: Path) -> dict[str, str]:
    """Read the assignments from an env fragment, ignoring comments."""
    variables = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        variables[name.strip()] = value.strip()
    return variables


def run_suricata(modbus_enabled: bool, rules: Path, work_dir: Path, image: str) -> dict:
    """Run Suricata over the committed capture and return what it produced."""
    if shutil.which("docker") is None:
        raise SystemExit("docker is required; it is not on PATH")
    shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True)
    command = [
        "docker", "run", "--rm",
        "-v", f"{rules.parent}:/rules:ro",
        "-v", f"{CAPTURE.parent}:/pcap:ro",
        "-v", f"{work_dir}:/out",
        image,
        "-r", f"/pcap/{CAPTURE.name}",
        "-S", f"/rules/{rules.name}",
        "--set", f"app-layer.protocols.modbus.enabled={'yes' if modbus_enabled else 'no'}",
        "-l", "/out",
    ]
    subprocess.run(command, check=True, capture_output=True)

    alerts = []
    eve = work_dir / "eve.json"
    if eve.exists():
        for line in eve.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("event_type") == "alert":
                alerts.append(
                    {
                        "sid": record["alert"]["signature_id"],
                        "has_app_layer_detail": "modbus" in record,
                    }
                )
    return {"modbus_parser_enabled": modbus_enabled, "alert_count": len(alerts), "alerts": alerts}


def check_app_layer(image: str, rules: Path) -> dict:
    """Prove the application-layer parser is what makes OT rules fire."""
    if not rules.exists():
        raise SystemExit(
            f"ruleset not found: {rules}\n"
            "Generate it with 'make deploy' in ot-detection-engineering."
        )
    work = Path("/tmp/ot-ndr-deployment")
    without = run_suricata(False, rules, work / "parser-off", image)
    with_parser = run_suricata(True, rules, work / "parser-on", image)

    if without["alert_count"] != 0:
        raise SystemExit(
            "expected no alerts with the Modbus parser disabled, got "
            f"{without['alert_count']}; the check no longer proves anything"
        )
    if with_parser["alert_count"] == 0:
        raise SystemExit("expected an alert with the Modbus parser enabled, got none")

    return {
        "capture": CAPTURE.name,
        "capture_sha256": sha256(CAPTURE),
        "rules": rules.name,
        "rules_sha256": sha256(rules),
        "image": image,
        "claim": "the Modbus application-layer parser is required for the OT rules to fire",
        "parser_disabled": without,
        "parser_enabled": with_parser,
        "sids_with_parser_enabled": sorted({a["sid"] for a in with_parser["alerts"]}),
    }


def malcolm_reads(malcolm_dir: Path, name: str) -> list[str]:
    """Files in the Malcolm checkout that read this environment variable.

    Neither of Malcolm's own lists is complete: the installer's
    config_env_var_keys.py covers what the configuration wizard prompts for, and
    the Suricata generator reads ``SURICATA_MODBUS_ENABLED`` by the bare name
    ``MODBUS_ENABLED`` after stripping the prefix. So the check is the general
    one — some script in the checkout reads it — searched under both spellings
    and restricted to code, because a ``config/*.env`` assignment is not a read.
    """
    candidates = [name, name.removeprefix("SURICATA_")]
    hits = []
    for directory in ("suricata", "pcap-capture", "zeek", "scripts", "arkime", "config"):
        root = malcolm_dir / directory
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in {".py", ".sh"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if any(candidate in text for candidate in candidates):
                hits.append(path.relative_to(malcolm_dir).as_posix())
    return hits


def check_malcolm_config(malcolm_dir: Path) -> dict:
    """Check the fragments against the components in Malcolm that read them."""
    generator = malcolm_dir / "suricata" / "scripts" / "suricata_config_populate.py"
    if not generator.exists():
        raise SystemExit(
            f"Malcolm generator not found at {generator}\n"
            "Pass --malcolm <malcolm checkout>, or clone Malcolm beside this repository."
        )
    source = generator.read_text(encoding="utf-8")
    # Variables the generator can read: keys of its DEFAULT_VARS literal plus the
    # names it looks up, since DISABLE_ICS_ALL is only ever read.
    generator_vars = set(re.findall(r"'([A-Z0-9_]+)'\s*:", source))
    generator_vars.update(re.findall(r"DEFAULT_VARS\[['\"]([A-Z0-9_]+)['\"]\]", source))

    findings = []
    unread = []
    for name, fragment in FRAGMENTS.items():
        variables = fragment_variables(fragment)
        readers = {}
        for variable in variables:
            where = malcolm_reads(malcolm_dir, variable)
            if where:
                readers[variable] = where[:3]
            else:
                unread.append(f"{name}: {variable}")
        findings.append(
            {
                "fragment": fragment.relative_to(REPO_ROOT).as_posix(),
                "fragment_sha256": sha256(fragment),
                "variables": dict(sorted(variables.items())),
                "read_by": readers,
            }
        )

    if unread:
        raise SystemExit(
            "these fragment variables are not read by anything in the Malcolm checkout:\n  "
            + "\n  ".join(unread)
        )

    # The ICS variables must also be the ones that gate parsing, not merely read.
    ics_missing = sorted(
        name for name in ("MODBUS_ENABLED", "MODBUS_EVE_ENABLED", "DNP3_ENABLED",
                          "DNP3_EVE_ENABLED", "DISABLE_ICS_ALL")
        if name not in generator_vars
    )
    if ics_missing:
        raise SystemExit(
            "the Suricata generator no longer reads: " + ", ".join(ics_missing)
        )

    revision = subprocess.run(
        ["git", "-C", str(malcolm_dir), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    )
    return {
        "malcolm_dir": str(malcolm_dir),
        "malcolm_revision": revision.stdout.strip() or "unknown",
        "generator_sha256": sha256(generator),
        "claim": "every variable the fragments set is read by a component in the "
                 "Malcolm checkout, and the ICS variables are the ones the Suricata "
                 "generator uses to gate Modbus/DNP3 parsing and EVE output",
        "ics_gate_variables": sorted(
            name for name in generator_vars
            if "ICS" in name or "MODBUS" in name or "DNP3" in name
        ),
        "fragments": findings,
        "note": "static check; the running-instance check is in deployment/README.md",
    }


def write_evidence(name: str, payload: dict) -> Path:
    """Write one check's evidence under deployment/evidence/."""
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    """Run the requested checks and write their evidence."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--malcolm", type=Path, default=DEFAULT_MALCOLM)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--only", choices=["app-layer", "malcolm-config"])
    args = parser.parse_args(argv)

    if args.only in (None, "app-layer"):
        evidence = write_evidence("app-layer", check_app_layer(args.image, args.rules))
        print(f"app-layer: parser off -> 0 alerts, parser on -> "
              f"{json.loads(evidence.read_text())['parser_enabled']['alert_count']} alert(s)")
        print(f"  -> {evidence.relative_to(REPO_ROOT)}")

    if args.only in (None, "malcolm-config"):
        evidence = write_evidence("malcolm-config", check_malcolm_config(args.malcolm))
        print(f"malcolm-config: fragments checked against {args.malcolm}")
        print(f"  -> {evidence.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
