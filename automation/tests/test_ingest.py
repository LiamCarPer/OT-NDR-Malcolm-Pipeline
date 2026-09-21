"""
Tests for the Malcolm NDR ingestion and forensic pipeline.

Two kinds of test live here. The unit tests mock the subprocess boundary so they
run anywhere. The capture tests read the committed PCAPs with the real tshark
binary, so the profile the pipeline reports is checked against the actual bytes
rather than against a fixture the test itself invented.
"""

import hashlib
import json
import os
import shutil
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path to import malcolm_ingest
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import malcolm_ingest  # noqa: E402

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PCAPS_DIR = os.path.join(PROJECT_DIR, "pcaps")
EVIDENCE_DIR = os.path.join(PROJECT_DIR, "detection-engineering", "evidence")

requires_tshark = pytest.mark.skipif(
    shutil.which("tshark") is None, reason="tshark is not installed"
)


def make_stats(**overrides):
    """Return a DPI stats dictionary with sensible defaults."""
    stats = {
        "modbus_requests": 1,
        "src_ips": ["172.24.0.10"],
        "dst_ips": ["172.21.0.10"],
        "primary_source": "172.24.0.10",
        "primary_target": "172.21.0.10",
        "func_codes": ["6"],
        "reads": 0,
        "writes": 1,
        "critical_writes": 1,
        "write_sources": ["172.24.0.10"],
        "mitre_tags": ["T0836", "T0855"],
    }
    stats.update(overrides)
    return stats


def test_calculate_sha256(tmp_path):
    """SHA-256 calculation is accurate."""
    content = b"forensic test pcap content"
    test_file = tmp_path / "forensic_test.pcap"
    test_file.write_bytes(content)

    assert malcolm_ingest.calculate_sha256(str(test_file)) == hashlib.sha256(content).hexdigest()


def test_calculate_sha256_missing_file_returns_none(tmp_path):
    """A missing file fails the hash instead of raising."""
    assert malcolm_ingest.calculate_sha256(str(tmp_path / "absent.pcap")) is None


@patch("malcolm_ingest.subprocess.run")
def test_analyze_pcap_dpi_basic(mock_run):
    """DPI analysis classifies reads and writes from tshark output."""
    mock_run.return_value = MagicMock(
        stdout="192.168.1.5\t192.168.1.10\t16\t1050\n192.168.1.5\t192.168.1.10\t3\t50",
        returncode=0,
    )

    stats = malcolm_ingest.analyze_pcap_dpi("mock.pcap")

    assert stats["modbus_requests"] == 2
    assert stats["reads"] == 1
    assert stats["writes"] == 1
    assert stats["critical_writes"] == 1
    assert stats["mitre_tags"] == ["T0836", "T0855"]


@patch("malcolm_ingest.subprocess.run")
def test_analyze_pcap_dpi_requests_only_filter(mock_run):
    """The tshark filter excludes responses, so operations are not double counted."""
    mock_run.return_value = MagicMock(stdout="", returncode=0)

    malcolm_ingest.analyze_pcap_dpi("mock.pcap")

    command = mock_run.call_args[0][0]
    assert "mbtcp && tcp.dstport == 502" in command


@patch("malcolm_ingest.subprocess.run", side_effect=FileNotFoundError("no tshark"))
def test_analyze_pcap_dpi_fails_loudly(mock_run):
    """A failed analysis returns None rather than a half-filled profile."""
    assert malcolm_ingest.analyze_pcap_dpi("mock.pcap") is None


@patch("malcolm_ingest.subprocess.run")
def test_sanitize_pcap_success(mock_run, tmp_path):
    """Sanitization triggers tcprewrite and creates the output directory."""
    mock_run.return_value = MagicMock(returncode=0)

    out = tmp_path / "nested" / "out.pcap"
    assert malcolm_ingest.sanitize_pcap("in.pcap", str(out)) is True
    assert out.parent.is_dir()
    mock_run.assert_called_once()


@patch("malcolm_ingest.subprocess.run", side_effect=FileNotFoundError("no tcprewrite"))
def test_sanitize_pcap_missing_tool_returns_false(mock_run):
    """A missing tcprewrite degrades to shipping the original, not a crash."""
    assert malcolm_ingest.sanitize_pcap("in.pcap", "out.pcap") is False


def test_generate_incident_report_content(tmp_path):
    """Report generation enriches the template with asset context."""
    template = tmp_path / "template.md"
    template.write_text(
        "Alert: {{ ALERT_MESSAGE }} | Target: {{ TARGET_ASSET }} | "
        "Criticality: {{ TARGET_CRITICALITY }} | Source auth: {{ SOURCE_AUTHORIZED }}"
    )
    inventory = {
        "172.21.0.10": {
            "name": "Production PLC",
            "zone": "Cell 1",
            "type": "PLC",
            "criticality": "CRITICAL",
            "owner": "OT-Admin",
            "control_writer": False,
        },
        "172.24.0.10": {"name": "HMI", "zone": "Cell 2", "control_writer": False},
    }

    with patch("malcolm_ingest.REPORT_TEMPLATE", str(template)), \
            patch("malcolm_ingest.REPORT_OUTPUT_DIR", str(tmp_path)), \
            patch("malcolm_ingest.load_inventory", return_value=inventory):
        report = malcolm_ingest.generate_incident_report(make_stats(), "test.pcap", "mockhash")

        assert report is not None
        content = open(report).read()
        assert "Unauthorized Modbus Setpoint Write" in content
        assert "Production PLC" in content
        assert "CRITICAL" in content
        assert "No (asset is not an allowlisted control writer)" in content


def test_report_omits_write_techniques_when_no_writes(tmp_path):
    """A read-only capture cannot produce a report claiming a write technique."""
    template = tmp_path / "template.md"
    template.write_text("{{ ALERT_MESSAGE }}\n{{ MITRE_ROWS }}\n")
    stats = make_stats(
        func_codes=["3"],
        reads=3,
        writes=0,
        critical_writes=0,
        write_sources=[],
        mitre_tags=["T0888"],
    )

    with patch("malcolm_ingest.REPORT_TEMPLATE", str(template)), \
            patch("malcolm_ingest.REPORT_OUTPUT_DIR", str(tmp_path)), \
            patch("malcolm_ingest.load_inventory", return_value={}):
        report = malcolm_ingest.generate_incident_report(stats, "recon.pcap", "hash")
        content = open(report).read()

    assert "T0888" in content
    assert "T0836" not in content
    assert "T0855" not in content
    assert "Write commands observed" not in content


def test_report_with_no_techniques_says_so(tmp_path):
    """A capture with nothing to assert renders an explicit empty row."""
    template = tmp_path / "template.md"
    template.write_text("{{ MITRE_ROWS }}")

    with patch("malcolm_ingest.REPORT_TEMPLATE", str(template)), \
            patch("malcolm_ingest.REPORT_OUTPUT_DIR", str(tmp_path)), \
            patch("malcolm_ingest.load_inventory", return_value={}):
        stats = make_stats(
            func_codes=["3"], reads=1, writes=0, critical_writes=0,
            write_sources=[], mitre_tags=[],
        )
        report = malcolm_ingest.generate_incident_report(stats, "baseline.pcap", "hash")
        content = open(report).read()

    assert "No ATT&CK for ICS technique is asserted" in content


def test_report_uses_write_source_not_busiest_talker(tmp_path):
    """The report names the source that wrote, not the host that talked most."""
    template = tmp_path / "template.md"
    template.write_text("Source: {{ SOURCE_IP }}")

    with patch("malcolm_ingest.REPORT_TEMPLATE", str(template)), \
            patch("malcolm_ingest.REPORT_OUTPUT_DIR", str(tmp_path)), \
            patch("malcolm_ingest.load_inventory", return_value={}):
        stats = make_stats(
            primary_source="172.21.0.20",           # busiest talker, read-only
            write_sources=["172.24.0.10"],          # the host that actually wrote
            src_ips=["172.21.0.20", "172.24.0.10"],
        )
        report = malcolm_ingest.generate_incident_report(stats, "mixed.pcap", "hash")
        content = open(report).read()

    assert "172.24.0.10" in content
    assert "172.21.0.20" not in content


def test_update_audit_log_appends_one_json_object_per_line(tmp_path):
    """The audit log stays machine readable: one JSON object per ingestion."""
    audit_log = tmp_path / "ingest_audit.log"

    with patch("malcolm_ingest.AUDIT_LOG", str(audit_log)):
        malcolm_ingest.update_audit_log("a.pcap", "abc", "SUCCESS", 10)
        malcolm_ingest.update_audit_log("b.pcap", "def", "FAILED (DPI error)", 20,
                                        sanitized_sha256="ghi")

    lines = audit_log.read_text().strip().splitlines()
    assert len(lines) == 2
    first, second = (json.loads(line) for line in lines)
    assert first["file"] == "a.pcap"
    assert first["status"] == "SUCCESS"
    assert first["timestamp"].endswith("Z")
    assert second["sanitized_sha256"] == "ghi"


def test_ingest_pcap_analyzes_original_when_sanitizing(tmp_path):
    """DPI runs on the evidence, never on the anonymized copy that ships."""
    source_dir = tmp_path / "pcaps"
    source_dir.mkdir()
    capture = source_dir / "sample.pcap"
    capture.write_bytes(b"original evidence bytes")
    sanitized = tmp_path / "sanitized.pcap"
    sanitized.write_bytes(b"anonymized bytes")
    sanitize_dir = tmp_path / "sanitize"
    sanitize_dir.mkdir()
    malcolm_dir = tmp_path / "malcolm"
    malcolm_dir.mkdir()
    analyzed = []

    with patch("malcolm_ingest.PCAP_SOURCE", str(source_dir)), \
            patch("malcolm_ingest.MALCOLM_PCAP_DIR", str(malcolm_dir)), \
            patch("malcolm_ingest.SANITIZE_DIR", str(sanitize_dir)), \
            patch("malcolm_ingest.AUDIT_LOG", str(tmp_path / "audit.log")), \
            patch("malcolm_ingest.REPORT_OUTPUT_DIR", str(tmp_path)), \
            patch("malcolm_ingest.analyze_pcap_dpi",
                  side_effect=lambda path: analyzed.append(path) or make_stats()), \
            patch("malcolm_ingest.sanitize_pcap", return_value=True) as mock_sanitize:
        mock_sanitize.side_effect = lambda src, dst: shutil.copy2(sanitized, dst) or True
        assert malcolm_ingest.ingest_pcap("sample.pcap", sanitize=True) is True

    assert analyzed == [str(capture)]
    assert (malcolm_dir / "sample.pcap").read_bytes() == b"anonymized bytes"


def test_ingest_pcap_records_audit_entry(tmp_path):
    """A successful ingest ships the capture and records its hash."""
    source_dir = tmp_path / "pcaps"
    source_dir.mkdir()
    capture = source_dir / "sample.pcap"
    capture.write_bytes(b"evidence")
    malcolm_dir = tmp_path / "malcolm"
    malcolm_dir.mkdir()
    audit_log = tmp_path / "audit.log"

    with patch("malcolm_ingest.PCAP_SOURCE", str(source_dir)), \
            patch("malcolm_ingest.MALCOLM_PCAP_DIR", str(malcolm_dir)), \
            patch("malcolm_ingest.AUDIT_LOG", str(audit_log)), \
            patch("malcolm_ingest.REPORT_OUTPUT_DIR", str(tmp_path)), \
            patch("malcolm_ingest.analyze_pcap_dpi", return_value=make_stats(writes=0)):
        assert malcolm_ingest.ingest_pcap("sample.pcap") is True

    assert (malcolm_dir / "sample.pcap").read_bytes() == b"evidence"
    entry = json.loads(audit_log.read_text().strip())
    assert entry["file"] == "sample.pcap"
    assert entry["sha256"] == hashlib.sha256(b"evidence").hexdigest()
    assert entry["status"] == "SUCCESS"


def test_ingest_pcap_fails_when_dpi_fails(tmp_path):
    """A capture whose analysis fails is not ingested and is recorded as failed."""
    source_dir = tmp_path / "pcaps"
    source_dir.mkdir()
    (source_dir / "sample.pcap").write_bytes(b"evidence")
    malcolm_dir = tmp_path / "malcolm"
    malcolm_dir.mkdir()
    audit_log = tmp_path / "audit.log"

    with patch("malcolm_ingest.PCAP_SOURCE", str(source_dir)), \
            patch("malcolm_ingest.MALCOLM_PCAP_DIR", str(malcolm_dir)), \
            patch("malcolm_ingest.AUDIT_LOG", str(audit_log)), \
            patch("malcolm_ingest.analyze_pcap_dpi", return_value=None):
        assert malcolm_ingest.ingest_pcap("sample.pcap") is False

    assert not (malcolm_dir / "sample.pcap").exists()
    assert json.loads(audit_log.read_text().strip())["status"] == "FAILED (DPI error)"


@requires_tshark
def test_baseline_capture_profile():
    """The benign capture is reads only, from a single master to a single PLC."""
    stats = malcolm_ingest.analyze_pcap_dpi(os.path.join(PCAPS_DIR, "baseline_modbus.pcap"))

    assert stats["modbus_requests"] == 610
    assert stats["reads"] == 610
    assert stats["writes"] == 0
    assert stats["critical_writes"] == 0
    assert stats["mitre_tags"] == []
    assert stats["src_ips"] == ["172.21.0.1"]
    assert stats["dst_ips"] == ["172.21.0.10"]


@requires_tshark
def test_recon_fanout_capture_profile():
    """Read-only fan-out across three control assets asserts discovery, not a write."""
    stats = malcolm_ingest.analyze_pcap_dpi(os.path.join(PCAPS_DIR, "modbus_recon_fanout.pcap"))

    assert stats["modbus_requests"] == 3
    assert stats["reads"] == 3
    assert stats["writes"] == 0
    assert stats["mitre_tags"] == ["T0888"]
    assert stats["dst_ips"] == ["172.21.0.10", "172.21.0.11", "172.21.0.12"]


@requires_tshark
def test_setpoint_write_capture_profile():
    """The write capture classifies one setpoint-class control operation."""
    stats = malcolm_ingest.analyze_pcap_dpi(os.path.join(PCAPS_DIR, "setpoint_write.pcap"))

    assert stats["modbus_requests"] == 7
    assert stats["reads"] == 6
    assert stats["writes"] == 1
    assert stats["critical_writes"] == 1
    assert stats["write_sources"] == ["172.24.0.10"]
    assert stats["mitre_tags"] == ["T0836", "T0855"]


def test_suricata_evidence_matches_committed_captures():
    """Committed alert evidence is tied to the exact bytes it was produced from."""
    for name in ("baseline_modbus", "modbus_recon_fanout", "setpoint_write"):
        capture = os.path.join(PCAPS_DIR, f"{name}.pcap")
        evidence = json.load(open(os.path.join(EVIDENCE_DIR, f"{name}.json")))

        assert evidence["capture"] == f"{name}.pcap"
        assert evidence["capture_sha256"] == malcolm_ingest.calculate_sha256(capture)


def test_suricata_evidence_records_expected_alerts():
    """The write capture is proven to fire SID 9000001; the benign one is quiet."""
    write_evidence = json.load(open(os.path.join(EVIDENCE_DIR, "setpoint_write.json")))
    baseline_evidence = json.load(open(os.path.join(EVIDENCE_DIR, "baseline_modbus.json")))

    assert [alert["sid"] for alert in write_evidence["alerts"]] == [9000001]
    assert write_evidence["alert_count"] == 1
    assert baseline_evidence["alert_count"] == 0


def test_asset_inventory_flags_control_writers():
    """The write allowlist lives in the asset model, not in a rule."""
    inventory = malcolm_ingest.load_inventory()

    writers = {ip for ip, asset in inventory.items() if asset.get("control_writer")}
    assert writers == {"172.21.0.20", "172.22.0.10"}
    assert inventory["172.24.0.10"]["control_writer"] is False
    assert all("zone" in asset for asset in inventory.values())
