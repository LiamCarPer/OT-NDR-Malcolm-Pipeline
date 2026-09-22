"""
Tests for the deployment layer: the watch service and the sensor configuration.

The watch behaviour is tested against the same pass function the loop uses, so
the loop is exercised rather than a test-only code path. The configuration is
tested by its evidence: the fragments and the capture they were verified against
are hashed, so editing either without re-running the verification fails here.
"""

import hashlib
import json
import os
import sys
from unittest.mock import patch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import malcolm_ingest  # noqa: E402

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEPLOYMENT = os.path.join(PROJECT_DIR, "deployment")
EVIDENCE = os.path.join(DEPLOYMENT, "evidence")

MATCHER_STATS = {
    "modbus_requests": 1,
    "src_ips": ["172.24.0.10"],
    "dst_ips": ["172.21.0.10"],
    "primary_source": "172.24.0.10",
    "primary_target": "172.21.0.10",
    "func_codes": ["3"],
    "reads": 1,
    "writes": 0,
    "critical_writes": 0,
    "write_sources": [],
    "mitre_tags": [],
    "first_event": None,
    "last_event": None,
    "first_write_event": None,
}


def sha256(path):
    """Return the SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            digest.update(block)
    return digest.hexdigest()


def audit_entries(path):
    """Return the audit log parsed into records, or an empty list."""
    if not os.path.exists(path):
        return []
    return [json.loads(line) for line in open(path) if line.strip()]


def watch_environment(tmp_path):
    """Return a watched directory that is also the Malcolm directory, as deployed."""
    watch = tmp_path / "incoming"
    watch.mkdir()
    audit = tmp_path / "ingest_audit.log"
    patches = (
        patch("malcolm_ingest.AUDIT_LOG", str(audit)),
        patch("malcolm_ingest.MALCOLM_PCAP_DIR", str(watch)),
        patch("malcolm_ingest.PCAP_SOURCE", str(tmp_path / "pcaps")),
        patch("malcolm_ingest.analyze_pcap_dpi", return_value=dict(MATCHER_STATS)),
    )
    return watch, audit, patches


def test_watch_ingests_each_capture_once(tmp_path):
    """A capture is ingested once, and a second pass leaves it alone."""
    watch, audit, patches = watch_environment(tmp_path)
    (watch / "capture.pcap").write_bytes(b"first capture")

    with patches[0], patches[1], patches[2], patches[3]:
        known, sizes = set(), {}
        # The first pass only learns the size: the writer may not be finished.
        known = malcolm_ingest.watch_pass(str(watch), known, sizes)
        assert audit_entries(audit) == []

        # The second pass sees a stable size and ingests it.
        known = malcolm_ingest.watch_pass(str(watch), known, sizes)
        entries = audit_entries(audit)
        assert len(entries) == 1
        assert entries[0]["file"] == "capture.pcap"
        assert entries[0]["status"] == "SUCCESS"

        # Every later pass skips it: the hash is already in the audit log.
        malcolm_ingest.watch_pass(str(watch), known, sizes)
        malcolm_ingest.watch_pass(str(watch), known, sizes)
        assert len(audit_entries(audit)) == 1


def test_watch_ignores_a_capture_still_being_written(tmp_path):
    """A file whose size keeps changing is left for a later pass."""
    watch, audit, patches = watch_environment(tmp_path)
    capture = watch / "growing.pcap"
    capture.write_bytes(b"partial")

    with patches[0], patches[1], patches[2], patches[3]:
        known, sizes = set(), {}
        malcolm_ingest.watch_pass(str(watch), known, sizes)
        capture.write_bytes(b"partial and still going")
        malcolm_ingest.watch_pass(str(watch), known, sizes)
        assert audit_entries(audit) == []

        # Once the size settles it is ingested.
        malcolm_ingest.watch_pass(str(watch), known, sizes)
        assert len(audit_entries(audit)) == 1


def test_watch_does_not_copy_a_capture_onto_itself(tmp_path):
    """In the deployed shape the capture is already in Malcolm's directory."""
    watch, audit, patches = watch_environment(tmp_path)
    capture = watch / "capture.pcap"
    capture.write_bytes(b"first capture")

    with patches[0], patches[1], patches[2], patches[3]:
        known, sizes = set(), {}
        malcolm_ingest.watch_pass(str(watch), known, sizes)
        malcolm_ingest.watch_pass(str(watch), known, sizes)

    assert capture.exists(), "the capture was moved or removed"
    assert audit_entries(audit)[0]["status"] == "SUCCESS"


def test_watch_skips_a_capture_already_in_the_audit_log(tmp_path):
    """Restarting the service does not re-ingest what it already ingested."""
    watch, audit, patches = watch_environment(tmp_path)
    content = b"already handled"
    (watch / "capture.pcap").write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    audit.write_text(json.dumps(
        {"timestamp": "2026-01-01T00:00:00Z", "file": "capture.pcap",
         "sha256": digest, "size_bytes": len(content), "status": "SUCCESS"}
    ) + "\n")

    with patches[0], patches[1], patches[2], patches[3]:
        known = malcolm_ingest.ingested_hashes()
        sizes = {}
        malcolm_ingest.watch_pass(str(watch), known, sizes)
        malcolm_ingest.watch_pass(str(watch), known, sizes)

    assert len(audit_entries(audit)) == 1


def test_ingested_hashes_ignores_failed_ingests(tmp_path):
    """Only a successful ingest counts as done, so a failure is retried."""
    watch, audit, patches = watch_environment(tmp_path)
    audit.write_text(
        json.dumps({"file": "a.pcap", "sha256": "aaa", "status": "FAILED (DPI error)"}) + "\n"
        + json.dumps({"file": "b.pcap", "sha256": "bbb", "status": "SUCCESS"}) + "\n"
    )

    with patches[0]:
        assert malcolm_ingest.ingested_hashes() == {"bbb"}


# --- deployment configuration evidence -----------------------------------

def test_app_layer_evidence_proves_the_parser_is_load_bearing():
    """The sensor claim rests on this: no parser, no alerts."""
    evidence = json.load(open(os.path.join(EVIDENCE, "app-layer.json")))

    assert evidence["capture_sha256"] == sha256(os.path.join(PROJECT_DIR, "pcaps",
                                                             evidence["capture"]))
    assert evidence["parser_disabled"]["alert_count"] == 0, (
        "the check only proves something if the rules stay quiet without the parser"
    )
    assert evidence["parser_enabled"]["alert_count"] > 0
    assert 9000001 in evidence["sids_with_parser_enabled"]


def test_malcolm_config_evidence_matches_the_fragments():
    """A fragment edited without re-running the verification fails here."""
    evidence = json.load(open(os.path.join(EVIDENCE, "malcolm-config.json")))

    assert evidence["fragments"], "no fragments were verified"
    for fragment in evidence["fragments"]:
        path = os.path.join(PROJECT_DIR, fragment["fragment"])
        assert os.path.exists(path), fragment["fragment"]
        assert fragment["fragment_sha256"] == sha256(path), (
            f"{fragment['fragment']} changed; re-run deployment/verify_deployment.py"
        )
        assert fragment["variables"], f"{fragment['fragment']} sets no variables"
        for variable, readers in fragment["read_by"].items():
            assert readers, f"{variable} is not read by anything in Malcolm"


def test_fragments_do_not_disable_ics_parsing():
    """The one setting that silently turns OT detection off must be false."""
    fragment = os.path.join(DEPLOYMENT, "malcolm", "config", "suricata.env.fragment")
    assignments = {}
    for line in open(fragment):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            name, _, value = line.partition("=")
            assignments[name.strip()] = value.strip()

    assert assignments["SURICATA_DISABLE_ICS_ALL"] == "false"
    for name in ("SURICATA_MODBUS_ENABLED", "SURICATA_MODBUS_EVE_ENABLED",
                 "SURICATA_DNP3_ENABLED", "SURICATA_DNP3_EVE_ENABLED"):
        assert assignments.get(name) == "true", f"{name} must be enabled for OT telemetry"


def test_service_unit_runs_the_watch_mode():
    """The unit has to run the service shape, not a one-shot ingest."""
    unit = open(os.path.join(DEPLOYMENT, "systemd", "ot-ndr-ingest.service")).read()

    assert "--watch" in unit
    assert "Restart=on-failure" in unit, "a watcher that dies quietly is worse than none"
    assert "MALCOLM_PCAP_DIR=" in unit, "the watched directory and the Malcolm directory must agree"
