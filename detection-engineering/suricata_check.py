#!/usr/bin/env python3
"""
Prove the generated ICS ruleset fires on this pipeline's captures.

The Suricata ruleset is maintained in ot-detection-engineering; this repository
consumes the generated artifact rather than duplicating it. This script runs
that artifact over the committed captures in a container, so the evidence
recorded here is a rule firing on the exact bytes this pipeline ingests - and,
just as importantly, records the captures it does *not* alert on.

Modbus and DNP3 application-layer detection is disabled in the stock Suricata
configuration, so the app-layer parsers are enabled explicitly.

Usage:
    python3 detection-engineering/suricata_check.py
    python3 detection-engineering/suricata_check.py --rules /path/to/ot-detection.rules
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURES_DIR = REPO_ROOT / "pcaps"
EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"
DEFAULT_IMAGE = "jasonish/suricata:latest"
DEFAULT_RULES = (
    REPO_ROOT.parent / "ot-detection-engineering" / "deploy" / "suricata" / "ot-detection.rules"
)

# Both parsers are off by default in the stock configuration.
SURICATA_SETS = [
    "app-layer.protocols.modbus.enabled=yes",
    "app-layer.protocols.dnp3.enabled=yes",
]


def sha256(path: Path) -> str:
    """Return the SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            digest.update(block)
    return digest.hexdigest()


def run_suricata(capture: Path, rules: Path, image: str, work_dir: Path) -> list[dict]:
    """Run Suricata over one capture and return the alert records it produced."""
    if shutil.which("docker") is None:
        sys.exit("docker is required to run Suricata; it is not on PATH")

    shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True)
    command = [
        "docker", "run", "--rm",
        "-v", f"{rules.parent}:/rules:ro",
        "-v", f"{capture.parent}:/pcap:ro",
        "-v", f"{work_dir}:/out",
        image,
        "-r", f"/pcap/{capture.name}",
        "-S", f"/rules/{rules.name}",
        *[arg for value in SURICATA_SETS for arg in ("--set", value)],
        "-l", "/out",
    ]
    subprocess.run(command, check=True)

    alerts = []
    eve = work_dir / "eve.json"
    if eve.exists():
        for line in eve.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("event_type") == "alert":
                alerts.append(record)
    return alerts


def main() -> None:
    """Run Suricata over every committed capture and record the alerts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES,
                        help="generated ruleset from ot-detection-engineering")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="Suricata container image")
    args = parser.parse_args()

    rules = args.rules.resolve()
    if not rules.exists():
        sys.exit(
            f"ruleset not found: {rules}\n"
            "Generate it with 'make deploy' in ot-detection-engineering."
        )

    EVIDENCE_DIR.mkdir(exist_ok=True)
    work_root = Path("/tmp/ot-ndr-suricata")
    for capture in sorted(CAPTURES_DIR.glob("*.pcap")):
        alerts = run_suricata(capture, rules, args.image, work_root / capture.stem)
        evidence = {
            "capture": capture.name,
            "capture_sha256": sha256(capture),
            "rules": rules.name,
            "rules_sha256": sha256(rules),
            "suricata_image": args.image,
            "alert_count": len(alerts),
            "alerts": [
                {
                    "sid": record["alert"]["signature_id"],
                    "signature": record["alert"]["signature"],
                    "timestamp": record["timestamp"],
                }
                for record in alerts
            ],
        }
        out = EVIDENCE_DIR / f"{capture.stem}.json"
        out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(f"{capture.name}: {len(alerts)} alert(s) -> {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
