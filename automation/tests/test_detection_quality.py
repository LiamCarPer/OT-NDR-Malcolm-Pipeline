"""
Tests for the detection-quality loop.

The metric is only worth having if it is derived and if it cannot be fudged, so
these tests pin the arithmetic, the latest-wins rule and the guards that stop a
disposition being recorded against something that never fired.
"""

import argparse
import json
import os
import sys
from unittest.mock import patch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import detection_quality  # noqa: E402


def write_records(path, rows):
    """Write a list of dictionaries as JSONL."""
    with open(path, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def make_environment(tmp_path, audit_rows, disposition_rows):
    """Patch the tool's paths at a temporary corpus."""
    audit = tmp_path / "ingest_audit.log"
    decisions = tmp_path / "dispositions.jsonl"
    write_records(audit, audit_rows)
    write_records(decisions, disposition_rows)
    return (
        patch.object(detection_quality, "AUDIT_LOG", str(audit)),
        patch.object(detection_quality, "DISPOSITIONS", str(decisions)),
    )


def test_rates_are_computed_from_fired_and_decided(tmp_path):
    """Correctness and actionability come from the joined data, not from a claim."""
    audit = [
        {"file": "a.pcap", "detections": ["sid:1", "dpi:write"]},
        {"file": "b.pcap", "detections": ["sid:1"]},
        {"file": "c.pcap", "detections": ["sid:1"]},
        {"file": "d.pcap", "detections": ["sid:2"]},
    ]
    decisions = [
        {"timestamp": "2026-01-01T00:00:00Z", "capture": "a.pcap", "disposition": "true_positive"},
        {"timestamp": "2026-01-02T00:00:00Z", "capture": "b.pcap",
         "disposition": "expected_change"},
        {"timestamp": "2026-01-03T00:00:00Z", "capture": "c.pcap", "disposition": "false_positive"},
        {"timestamp": "2026-01-04T00:00:00Z", "capture": "d.pcap", "disposition": "inconclusive"},
    ]
    audit_patch, decisions_patch = make_environment(tmp_path, audit, decisions)

    with audit_patch, decisions_patch:
        rows, _ = detection_quality.compute()

    by_key = {row["detection"]: row for row in rows}
    # One true positive, one expected change, one false positive: correctness 2/3.
    assert by_key["sid:1"]["correctness"] == "67%"
    # One true positive out of three resolved: actionability 1/3.
    assert by_key["sid:1"]["actionability"] == "33%"
    assert by_key["sid:1"]["reviewed"] == 3
    # Inconclusive is counted but excluded from both rates.
    assert by_key["sid:2"]["counts"]["inconclusive"] == 1
    assert by_key["sid:2"]["correctness"] == "—"
    assert by_key["sid:2"]["actionability"] == "—"


def test_reingesting_a_capture_does_not_inflate_triggers(tmp_path):
    """Triggers count captures, not log lines, so re-runs cannot pad the metric."""
    audit = [
        {"file": "a.pcap", "detections": ["sid:1"]},
        {"file": "a.pcap", "detections": ["sid:1"]},
        {"file": "a.pcap", "detections": ["sid:1"]},
    ]
    audit_patch, decisions_patch = make_environment(tmp_path, audit, [])

    with audit_patch, decisions_patch:
        rows, _ = detection_quality.compute()

    assert rows[0]["triggers"] == ["a.pcap"]
    assert rows[0]["unreviewed"] == 1


def test_latest_disposition_wins(tmp_path):
    """Re-triaging a capture replaces the earlier decision."""
    decisions = [
        {"timestamp": "2026-01-01T00:00:00Z", "capture": "a.pcap", "disposition": "inconclusive"},
        {"timestamp": "2026-02-01T00:00:00Z", "capture": "a.pcap", "disposition": "true_positive"},
    ]
    audit_patch, decisions_patch = make_environment(
        tmp_path, [{"file": "a.pcap", "detections": ["sid:1"]}], decisions
    )

    with audit_patch, decisions_patch:
        rows, _ = detection_quality.compute()

    assert rows[0]["counts"]["true_positive"] == 1
    assert rows[0]["counts"]["inconclusive"] == 0


def test_captures_without_detections_are_not_metrics(tmp_path):
    """An entry written before detections were recorded must not be counted."""
    audit = [{"file": "old.pcap", "sha256": "x", "status": "SUCCESS"}]
    audit_patch, decisions_patch = make_environment(tmp_path, audit, [])

    with audit_patch, decisions_patch:
        rows, _ = detection_quality.compute()

    assert rows == []


def test_tuning_actions_name_the_problem(tmp_path):
    """Each non-actionable outcome produces a specific action, not a generic one."""
    audit = [
        {"file": "good.pcap", "detections": ["sid:1"]},
        {"file": "noisy.pcap", "detections": ["sid:2"]},
        {"file": "wrong.pcap", "detections": ["sid:3"]},
        {"file": "unread.pcap", "detections": ["sid:4"]},
    ]
    decisions = [
        {"timestamp": "2026-01-01T00:00:00Z", "capture": "good.pcap",
         "disposition": "true_positive"},
        {"timestamp": "2026-01-01T00:00:00Z", "capture": "noisy.pcap",
         "disposition": "expected_change"},
        {"timestamp": "2026-01-01T00:00:00Z", "capture": "wrong.pcap",
         "disposition": "false_positive"},
    ]
    audit_patch, decisions_patch = make_environment(tmp_path, audit, decisions)

    with audit_patch, decisions_patch:
        rows, _ = detection_quality.compute()
        actions = "\n".join(detection_quality.tuning_actions(rows))

    assert "sid:2" in actions and "approved work" in actions
    assert "sid:3" in actions and "Fix the detection logic" in actions
    assert "sid:4" in actions and "no disposition" in actions
    assert "sid:1" not in actions


def test_record_rejects_an_unknown_disposition(tmp_path):
    """A typo in the disposition is refused rather than written to the record."""
    audit_patch, decisions_patch = make_environment(
        tmp_path, [{"file": "a.pcap", "detections": ["sid:1"]}], []
    )
    args = argparse.Namespace(capture="a.pcap", disposition="probably_fine", analyst="a", note="")

    with audit_patch, decisions_patch, \
            patch.object(detection_quality, "PCAP_SOURCE", str(tmp_path)):
        assert detection_quality.record(args) == 1


def test_record_rejects_a_detection_that_never_fired(tmp_path):
    """A disposition cannot be recorded against a capture with no detections."""
    audit_patch, decisions_patch = make_environment(tmp_path, [], [])
    (tmp_path / "a.pcap").write_bytes(b"x")
    args = argparse.Namespace(
        capture="a.pcap", disposition="true_positive", analyst="a", note=""
    )

    with audit_patch, decisions_patch, \
            patch.object(detection_quality, "PCAP_SOURCE", str(tmp_path)):
        assert detection_quality.record(args) == 1


def test_record_appends_the_covered_detections(tmp_path):
    """A disposition records which detections it covers, for provenance."""
    audit_patch, decisions_patch = make_environment(
        tmp_path, [{"file": "a.pcap", "detections": ["sid:1", "dpi:write"]}], []
    )
    (tmp_path / "a.pcap").write_bytes(b"x")
    decisions = tmp_path / "dispositions.jsonl"
    args = argparse.Namespace(
        capture="a.pcap", disposition="true_positive", analyst="analyst", note="note"
    )

    with audit_patch, decisions_patch, \
            patch.object(detection_quality, "PCAP_SOURCE", str(tmp_path)):
        assert detection_quality.record(args) == 0

    written = json.loads(decisions.read_text().strip())
    assert written["capture"] == "a.pcap"
    assert written["detections"] == ["dpi:write", "sid:1"]
    assert written["disposition"] == "true_positive"
    assert written["analyst"] == "analyst"


def test_rendered_report_defines_its_rates(tmp_path):
    """The committed report has to say what its numbers mean and what they miss."""
    audit_patch, decisions_patch = make_environment(
        tmp_path,
        [{"file": "a.pcap", "detections": ["sid:1"]}],
        [{"timestamp": "2026-01-01T00:00:00Z", "capture": "a.pcap",
          "disposition": "true_positive"}],
    )

    with audit_patch, decisions_patch:
        rows, decisions = detection_quality.compute()
        report = detection_quality.render(rows, decisions)

    assert "Correctness" in report and "Actionability" in report
    assert "not independent" in report
    assert "unread queue" in report
