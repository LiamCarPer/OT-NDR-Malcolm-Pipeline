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
ATTACK_ICS_CATALOG = os.path.join(
    os.path.dirname(PROJECT_DIR), "ot-detection-engineering", "metadata", "attack_ics_catalog.json"
)
CHANGE_WINDOWS = os.path.join(PROJECT_DIR, "automation", "change_windows.json")

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
        "mitre_tags": ["T0836", "T1692.001"],
        "first_event": None,
        "last_event": None,
        "first_write_event": None,
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
    assert stats["mitre_tags"] == ["T0836", "T1692.001"]


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
    assert "T1692.001" not in content
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
    assert stats["mitre_tags"] == ["T0836", "T1692.001"]


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


@pytest.mark.skipif(
    not os.path.exists(ATTACK_ICS_CATALOG),
    reason="ot-detection-engineering checkout is not available",
)
def test_mitre_techniques_match_pinned_catalog():
    """
    Assert every asserted technique exists in the pinned ATT&CK for ICS catalog.

    The name the report prints must match the catalog too. This is the guard that
    catches a deprecated or renumbered technique: the pipeline used to assert
    T0855, which was removed when the ICS techniques were restructured.
    """
    catalog = {
        technique["id"]: technique["name"]
        for technique in json.load(open(ATTACK_ICS_CATALOG))["techniques"]
    }
    assert catalog, "the pinned catalog is empty"

    for technique, (name, _) in malcolm_ingest.MITRE_TECHNIQUES.items():
        assert technique in catalog, f"{technique} is not in the pinned catalog"
        assert catalog[technique] == name, (
            f"{technique} is '{catalog[technique]}' in the catalog, not '{name}'"
        )


# --- Severity model -------------------------------------------------------

@pytest.mark.parametrize(
    "operation,criticality,within_window,expected",
    [
        ("setpoint_write", "High", False, "CRITICAL"),
        ("setpoint_write", "High", True, "HIGH"),
        ("setpoint_write", "Medium", False, "HIGH"),
        ("setpoint_write", "Medium", True, "MEDIUM"),
        ("setpoint_write", "Low", True, "LOW"),
        ("write", "High", False, "HIGH"),
        ("write", "High", True, "MEDIUM"),
        ("write", "Medium", False, "MEDIUM"),
        ("write", "Medium", True, "LOW"),
        ("read_fanout", "High", False, "MEDIUM"),
        ("drift", "High", False, "MEDIUM"),
    ],
)
def test_severity_matrix(operation, criticality, within_window, expected):
    """Severity is a function of the operation, the asset and the change calendar."""
    assert malcolm_ingest.severity_for(operation, criticality, within_window) == expected


def test_unknown_criticality_is_not_downgraded():
    """An asset nobody has classified is not treated as unimportant."""
    assert malcolm_ingest.severity_for("setpoint_write", "Unknown", False) == "CRITICAL"


def test_severity_basis_names_the_inputs():
    """The report has to justify its severity, not just assert it."""
    basis = malcolm_ingest.severity_basis(
        "setpoint_write", "High", {"id": "CHG-1", "reason": "setpoint recalibration"}
    )
    assert "setpoint-class write" in basis.lower()
    assert "high-criticality" in basis
    assert "CHG-1" in basis

    without = malcolm_ingest.severity_basis("drift", "High", None)
    assert "no approved change window" in without


def test_change_window_matches_asset_operation_and_event_time(tmp_path):
    """A window only covers the asset, operation and period it was written for."""
    windows = tmp_path / "change_windows.json"
    windows.write_text(json.dumps({"windows": [{
        "id": "CHG-1",
        "assets": ["10.0.0.1"],
        "operations": ["setpoint_write"],
        "start": "2026-05-02T02:00:00Z",
        "end": "2026-05-02T04:00:00Z",
    }]}))

    inside = malcolm_ingest.parse_utc("2026-05-02T02:16:00Z")
    outside = malcolm_ingest.parse_utc("2026-05-01T10:31:00Z")

    with patch("malcolm_ingest.CHANGE_WINDOWS", str(windows)):
        assert malcolm_ingest.find_change_window(
            "10.0.0.1", "setpoint_write", inside)["id"] == "CHG-1"
        assert malcolm_ingest.find_change_window("10.0.0.1", "setpoint_write", outside) is None
        assert malcolm_ingest.find_change_window("10.0.0.9", "setpoint_write", inside) is None
        assert malcolm_ingest.find_change_window("10.0.0.1", "drift", inside) is None
        assert malcolm_ingest.find_change_window("10.0.0.1", "setpoint_write", None) is None


def test_missing_change_window_file_is_not_an_error(tmp_path):
    """A deployment with no change calendar still works; nothing is covered."""
    with patch("malcolm_ingest.CHANGE_WINDOWS", str(tmp_path / "absent.json")):
        assert malcolm_ingest.load_change_windows() == []
        assert malcolm_ingest.find_change_window(
            "10.0.0.1", "setpoint_write", malcolm_ingest.parse_utc("2026-05-02T02:16:00Z")
        ) is None


# --- Alert triggering -----------------------------------------------------

def test_load_alerts_from_evidence_file():
    """The evidence file names the capture, so --file can be omitted."""
    alerts, capture = malcolm_ingest.load_alerts(
        os.path.join(EVIDENCE_DIR, "setpoint_write.json")
    )

    assert capture == "setpoint_write.pcap"
    assert [alert["sid"] for alert in alerts] == [9000001]
    assert "Write Single Register" in alerts[0]["signature"]


def test_load_alerts_from_eve_jsonl(tmp_path):
    """A raw Suricata eve.json is JSONL and carries alert plus non-alert records."""
    eve = tmp_path / "eve.json"
    eve.write_text(
        '{"timestamp":"2026-05-01T10:32:00.020001+0000","event_type":"alert",'
        '"alert":{"signature_id":9000001,"signature":"OT Modbus Write"}}\n'
        '{"timestamp":"2026-05-01T10:32:01.000000+0000","event_type":"flow"}\n'
    )

    alerts, capture = malcolm_ingest.load_alerts(str(eve))

    assert capture is None
    assert len(alerts) == 1
    assert alerts[0]["sid"] == 9000001
    assert alerts[0]["signature"] == "OT Modbus Write"


def test_derive_detections_lists_alerts_before_the_profiler():
    """Detection keys are the join between what fired and what an analyst decided."""
    detections = malcolm_ingest.derive_detections(make_stats(), [{"sid": 9000001}])

    assert detections == ["sid:9000001", "dpi:setpoint_write"]


def test_ingest_refuses_evidence_for_a_different_capture(tmp_path):
    """Wiring the wrong evidence to a capture would describe the wrong bytes."""
    source_dir = tmp_path / "pcaps"
    source_dir.mkdir()
    (source_dir / "a.pcap").write_bytes(b"a")
    (source_dir / "b.pcap").write_bytes(b"b")
    evidence = tmp_path / "b.json"
    evidence.write_text(json.dumps({
        "capture": "b.pcap",
        "alerts": [{"sid": 9000001, "signature": "x", "timestamp": "y"}],
    }))
    audit_log = tmp_path / "audit.log"

    with patch("malcolm_ingest.PCAP_SOURCE", str(source_dir)), \
            patch("malcolm_ingest.AUDIT_LOG", str(audit_log)):
        assert malcolm_ingest.ingest_pcap("a.pcap", alerts_path=str(evidence)) is False

    assert not audit_log.exists()


def test_ingest_records_trigger_and_detections(tmp_path):
    """The audit record is the join table the quality metric is built on."""
    source_dir = tmp_path / "pcaps"
    source_dir.mkdir()
    (source_dir / "sample.pcap").write_bytes(b"evidence")
    audit_log = tmp_path / "audit.log"

    with patch("malcolm_ingest.PCAP_SOURCE", str(source_dir)), \
            patch("malcolm_ingest.AUDIT_LOG", str(audit_log)), \
            patch("malcolm_ingest.MALCOLM_PCAP_DIR", str(tmp_path / "none")), \
            patch("malcolm_ingest.REPORT_OUTPUT_DIR", str(tmp_path)), \
            patch("malcolm_ingest.analyze_pcap_dpi", return_value=make_stats()):
        assert malcolm_ingest.ingest_pcap("sample.pcap") is True

    entry = json.loads(audit_log.read_text().strip())
    assert entry["trigger"] == "profiler"
    assert entry["detections"] == ["dpi:setpoint_write"]


# --- Event time and the change calendar, against the committed captures ----

@requires_tshark
def test_event_times_come_from_the_capture_not_the_clock():
    """Reports describe when the traffic happened, not when the pipeline ran."""
    stats = malcolm_ingest.analyze_pcap_dpi(os.path.join(PCAPS_DIR, "setpoint_write.pcap"))

    assert stats["first_event"].strftime("%Y-%m-%d %H:%M") == "2026-05-01 10:31"
    assert stats["last_event"].strftime("%Y-%m-%d %H:%M") == "2026-05-01 10:32"
    assert stats["first_write_event"].strftime("%Y-%m-%d %H:%M") == "2026-05-01 10:32"


@requires_tshark
def test_maintenance_capture_profile():
    """The maintenance capture carries the same classification as the attack one."""
    stats = malcolm_ingest.analyze_pcap_dpi(
        os.path.join(PCAPS_DIR, "setpoint_write_maintenance.pcap")
    )

    assert stats["writes"] == 1
    assert stats["critical_writes"] == 1
    assert stats["mitre_tags"] == ["T0836", "T1692.001"]


@requires_tshark
def test_same_detection_different_context_is_reported_differently():
    """
    The headline of the tuning model: identical detection, different severity.

    Both captures are the same class of operation from a non-allowlisted writer.
    One falls inside an approved change window and one does not, and that alone
    moves the report from CRITICAL to HIGH.
    """
    plain = malcolm_ingest.build_report_context(
        malcolm_ingest.analyze_pcap_dpi(os.path.join(PCAPS_DIR, "setpoint_write.pcap")),
        "setpoint_write.pcap",
    )
    in_window = malcolm_ingest.build_report_context(
        malcolm_ingest.analyze_pcap_dpi(
            os.path.join(PCAPS_DIR, "setpoint_write_maintenance.pcap")
        ),
        "setpoint_write_maintenance.pcap",
    )

    assert plain["window"] is None
    assert plain["severity"] == "CRITICAL"
    assert plain["detections"] == ["dpi:setpoint_write"]

    assert in_window["window"]["id"] == "CHG-1042"
    assert in_window["severity"] == "HIGH"
    # The source is still not an allowlisted writer in either case.
    assert in_window["authorized"].startswith("No")


@requires_tshark
def test_committed_change_window_file_is_valid():
    """The committed calendar parses and covers the capture it is meant to."""
    windows = malcolm_ingest.load_change_windows()

    assert windows, f"{CHANGE_WINDOWS} should declare at least one window"
    for window in windows:
        assert malcolm_ingest.parse_utc(window["start"]) < malcolm_ingest.parse_utc(window["end"])
        assert window["id"] and window["owner"] and window["reason"]

    maintenance = malcolm_ingest.find_change_window(
        "172.21.0.10", "setpoint_write", malcolm_ingest.parse_utc("2026-05-02T02:16:00Z")
    )
    assert maintenance is not None
    assert malcolm_ingest.find_change_window(
        "172.21.0.10", "setpoint_write", malcolm_ingest.parse_utc("2026-05-01T10:32:00Z")
    ) is None


def test_readme_quality_table_matches_the_generated_metric():
    """
    The README quotes derived numbers, so a stale headline has to fail.

    This is the same discipline the sibling repository applies to its coverage
    table: if a number is worth publishing, something should break when it stops
    being true.
    """
    with open(os.path.join(PROJECT_DIR, "metrics", "detection-quality.md")) as f:
        metrics = f.read()
    with open(os.path.join(PROJECT_DIR, "README.md")) as f:
        readme = f.read()

    rows = [
        line for line in metrics.splitlines()
        if line.startswith("| `") and ".pcap" in line
    ]
    assert rows, "the per-detection metric rows are missing"

    for row in rows:
        assert row in readme, f"README is stale for: {row[:70]}"
