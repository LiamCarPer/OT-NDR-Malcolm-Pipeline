#!/usr/bin/env python3
"""
Malcolm NDR ingestion and forensic profiler.

Automates PCAP ingestion into CISA Malcolm with pre-analysis DPI, asset-context
enrichment, NIST-aligned incident reporting and an append-only forensic audit
log.

Author: Liam Carvajal (@LiamCarPer)
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone

# --- System configuration ---
MALCOLM_PCAP_DIR = os.environ.get("MALCOLM_PCAP_DIR", "/opt/Malcolm/pcap")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
PCAP_SOURCE = os.path.join(PROJECT_DIR, "pcaps")
AUDIT_LOG = os.path.join(SCRIPT_DIR, "ingest_audit.log")
ASSET_INVENTORY = os.path.join(SCRIPT_DIR, "asset_inventory.json")
CHANGE_WINDOWS = os.path.join(SCRIPT_DIR, "change_windows.json")
REPORT_TEMPLATE = os.path.join(PROJECT_DIR, "incident-response", "Incident_Report_Template.md")
REPORT_OUTPUT_DIR = os.path.join(PROJECT_DIR, "incident-response")
SANITIZE_DIR = os.path.join(tempfile.gettempdir(), "ot-ndr-sanitized")

# --- Modbus/TCP semantics ---
# Function codes 1-4 are read operations, 5/6/15/16 write to the device, and
# registers at or above 1000 are treated as setpoint-class in this lab.
READ_FUNCTIONS = {"1", "2", "3", "4"}
WRITE_FUNCTIONS = {"5", "6", "15", "16"}
SETPOINT_REGISTER_FLOOR = 1000

# --- Severity model ---
# Severity is derived from three inputs, not from the operation alone: what was
# done, how much the asset matters, and whether an approved change window covers
# the event. The adjustment is applied to the operation's base severity and
# clamped, so the model stays explainable in the report.
SEVERITY_STEPS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
OPERATION_SEVERITY = {
    "setpoint_write": "CRITICAL",
    "write": "HIGH",
    "read_fanout": "MEDIUM",
    "drift": "MEDIUM",
}
# A write inside an approved change window is not unauthorised by timing, so it
# is named for what it is; the source is still checked separately.
OPERATION_LABELS = {
    "setpoint_write": ("Unauthorized Modbus Setpoint Write", "Unauthorized Setpoint Manipulation"),
    "write": ("Unauthorized Modbus Write", "Unauthorized Command Execution"),
    "read_fanout": ("Modbus Read Enumeration", "Reconnaissance"),
    "drift": ("Modbus Baseline Drift", "Baseline Drift"),
}
WINDOW_LABELS = {
    "setpoint_write": (
        "Modbus Setpoint Write During Approved Change Window",
        "Setpoint Manipulation During Approved Change Window",
    ),
    "write": (
        "Modbus Write During Approved Change Window",
        "Control Write During Approved Change Window",
    ),
}
CRITICALITY_ADJUSTMENT = {"critical": 0, "high": 0, "medium": -1, "low": -2}
# An asset with no recorded criticality is not downgraded: unknown is not low.
CRITICALITY_DEFAULT = 0

# ATT&CK for ICS techniques this DPI heuristic can assert, and the evidence
# required for each one. Techniques are never hardcoded into a report: they are
# derived from the observed operations, so a capture with no control writes
# cannot claim a write technique. IDs and names are validated against the pinned
# ATT&CK for ICS catalog in ot-detection-engineering by the test suite.
MITRE_TECHNIQUES = {
    "T0836": ("Modify Parameter", "Modbus write commands observed."),
    "T1692.001": (
        "Command Message",
        "Write to a setpoint-class register (>= 1000).",
    ),
    "T0888": (
        "Remote System Information Discovery",
        "Read-only requests fanning out across several control assets.",
    ),
}

# Timestamps are UTC in both the progress log and the audit log, so the two can
# be read side by side without a timezone conversion.
logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("NDR-Pipeline")


def load_inventory():
    """Load the asset inventory used for context enrichment."""
    if os.path.exists(ASSET_INVENTORY):
        try:
            with open(ASSET_INVENTORY) as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error("Failed to decode asset inventory JSON.")
    return {}


def load_change_windows():
    """Load approved change windows, if the file exists."""
    if not os.path.exists(CHANGE_WINDOWS):
        return []
    try:
        with open(CHANGE_WINDOWS) as f:
            return json.load(f).get("windows", [])
    except json.JSONDecodeError:
        logger.error("Failed to decode change window JSON.")
        return []


def parse_utc(value):
    """Parse an ISO-8601 timestamp, treating a trailing Z as UTC."""
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def find_change_window(asset, operation, when):
    """
    Return the approved change window covering this event, or None.

    The window is matched on the asset, the operation class and the event time
    taken from the capture - not the time the pipeline happens to run, which
    would let a later ingest silently mismatch an earlier event.
    """
    if when is None:
        return None
    for window in load_change_windows():
        assets = window.get("assets", [])
        if asset not in assets and "*" not in assets:
            continue
        operations = window.get("operations", [])
        if operation not in operations and "any" not in operations:
            continue
        if parse_utc(window["start"]) <= when <= parse_utc(window["end"]):
            return window
    return None


def operation_class(stats):
    """Classify what the capture actually contains, most severe first."""
    if stats.get("critical_writes"):
        return "setpoint_write"
    if stats.get("writes"):
        return "write"
    if stats.get("reads") and len(stats.get("dst_ips", [])) > 1:
        return "read_fanout"
    return "drift"


def severity_for(operation, criticality, within_window):
    """Derive severity from the operation, the asset criticality and the window."""
    index = SEVERITY_STEPS.index(OPERATION_SEVERITY[operation])
    index += CRITICALITY_ADJUSTMENT.get(str(criticality).lower(), CRITICALITY_DEFAULT)
    if within_window:
        index -= 1
    return SEVERITY_STEPS[max(0, min(len(SEVERITY_STEPS) - 1, index))]


def severity_basis(operation, criticality, window):
    """Explain the severity in one sentence an analyst can check."""
    described = {
        "setpoint_write": "Setpoint-class write",
        "write": "Control write",
        "read_fanout": "Read-only fan-out across control assets",
        "drift": "Read-only traffic with no control operation",
    }[operation]
    level = str(criticality or "unknown").lower()
    if window:
        timing = (
            f"the event falls inside approved change window {window['id']} "
            f"({window.get('reason', 'no reason recorded')})"
        )
    else:
        timing = "no approved change window covers the event"
    return f"{described} against a {level}-criticality asset, and {timing}."


def calculate_sha256(file_path):
    """Calculate the SHA-256 digest of a file for forensic integrity."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except OSError as e:
        logger.error(f"Hash calculation failed for {file_path}: {e}")
        return None


def update_audit_log(file_name, sha256, status, size_bytes, **fields):
    """
    Append one record to the forensic audit log.

    The log is append-only and machine readable: exactly one JSON object per
    line, one line per ingestion, timestamps in UTC. Progress output stays on
    stdout so human log lines can never mix with the custody record.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file": file_name,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "status": status,
    }
    entry.update(fields)
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.error(f"Failed to update audit log: {e}")


def sanitize_pcap(input_path, output_path):
    """
    Write an anonymized copy of a capture for privacy before it leaves the lab.

    Requires tcprewrite (part of the tcpreplay suite). Returns True when the
    sanitized copy was written. Sanitization is only ever applied to the copy
    that is shipped, never to the evidence that is analyzed.
    """
    logger.info(f"Initiating privacy sanitization for {os.path.basename(input_path)}...")
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        # Anonymize IPs by mapping them into the 10.0.0.0/8 range.
        cmd = [
            "tcprewrite",
            "--pnat=0.0.0.0/0:10.0.0.0/8",
            "--infile=" + input_path,
            "--outfile=" + output_path,
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        logger.info(f"Sanitization complete. Sanitized copy: {output_path}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("tcprewrite not found or failed. Shipping the original capture.")
        return False


def analyze_pcap_dpi(file_path):
    """
    Profile Modbus/TCP traffic and derive ATT&CK for ICS techniques.

    The whole capture is read, so the counts are exact and never silently
    truncated. Event times come from the capture itself, not from the clock, so
    a report describes when the traffic happened rather than when it was
    processed. Returns None if the analysis could not run, so the caller fails
    loudly instead of reporting a partial profile as a result.
    """
    logger.info(f"Starting deep packet inspection (DPI) for {os.path.basename(file_path)}")

    stats = {
        "modbus_requests": 0,
        "src_ips": [],
        "dst_ips": [],
        "primary_source": "Unknown",
        "primary_target": "Unknown",
        "func_codes": [],
        "reads": 0,
        "writes": 0,
        "critical_writes": 0,
        "mitre_tags": [],
        "first_event": None,
        "last_event": None,
        "first_write_event": None,
    }

    try:
        # `mbtcp` matches Modbus responses as well as requests. Narrowing the
        # filter to traffic addressed to the Modbus server port keeps the counts
        # to one entry per request; otherwise every operation is counted twice
        # and a PLC's write *response* looks like a write originating from the PLC.
        cmd = [
            "tshark",
            "-r", file_path,
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "modbus.func_code",
            "-e", "modbus.reference_num",
            "-e", "frame.time_epoch",
            "-Y", "mbtcp && tcp.dstport == 502",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.error(f"DPI analysis failed: {e}")
        return None

    lines = [line for line in result.stdout.splitlines() if line]
    if not lines:
        logger.warning("No Modbus TCP traffic identified in capture.")
        return stats

    src_ips, dst_ips, func_codes, references, times = [], [], [], [], []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2]:
            continue
        src_ips.append(parts[0])
        dst_ips.append(parts[1])
        func_codes.append(parts[2].split(",")[0])
        references.append(parts[3] if len(parts) > 3 else "")
        times.append(parts[4] if len(parts) > 4 else "")

    stats["src_ips"] = sorted(set(src_ips))
    stats["dst_ips"] = sorted(set(dst_ips))
    stats["func_codes"] = sorted(set(func_codes))
    stats["modbus_requests"] = len(func_codes)
    # Deterministic, and semantically meaningful: the asset that carried the
    # most traffic. A set() would make reports irreproducible across runs.
    stats["primary_source"] = Counter(src_ips).most_common(1)[0][0]
    stats["primary_target"] = Counter(dst_ips).most_common(1)[0][0]
    # The source of the control operations is the one an analyst has to triage
    # and it is not necessarily the busiest talker, so it is tracked separately.
    stats["write_sources"] = [
        source
        for source, _ in Counter(
            src for src, code in zip(src_ips, func_codes) if code in WRITE_FUNCTIONS
        ).most_common()
    ]

    code_counts = Counter(func_codes)
    stats["reads"] = sum(n for code, n in code_counts.items() if code in READ_FUNCTIONS)
    stats["writes"] = sum(n for code, n in code_counts.items() if code in WRITE_FUNCTIONS)
    stats["critical_writes"] = sum(
        1
        for code, reference in zip(func_codes, references)
        if code in WRITE_FUNCTIONS and reference.isdigit()
        and int(reference) >= SETPOINT_REGISTER_FLOOR
    )

    epoch_times = [float(value) for value in times if value]
    if epoch_times:
        stats["first_event"] = datetime.fromtimestamp(min(epoch_times), timezone.utc)
        stats["last_event"] = datetime.fromtimestamp(max(epoch_times), timezone.utc)
    write_times = [
        float(value)
        for value, code in zip(times, func_codes)
        if value and code in WRITE_FUNCTIONS
    ]
    if write_times:
        stats["first_write_event"] = datetime.fromtimestamp(min(write_times), timezone.utc)

    tags = []
    if stats["writes"]:
        tags.append("T0836")
    if stats["critical_writes"]:
        tags.append("T1692.001")
    if stats["reads"] and not stats["writes"] and len(stats["dst_ips"]) > 1:
        tags.append("T0888")
    stats["mitre_tags"] = tags

    logger.info(f"DPI summary: {stats['modbus_requests']} Modbus requests analysed.")
    logger.info(
        f"Operations: Reads={stats['reads']}, Writes={stats['writes']} "
        f"(Critical={stats['critical_writes']})"
    )
    logger.info(
        f"ATT&CK for ICS: {', '.join(tags) if tags else 'no technique asserted'}"
    )
    return stats


def load_alerts(path):
    """
    Read the alerts that triggered this report.

    Two shapes are accepted: a Suricata eve.json (JSONL, or a JSON array), and
    the alert-evidence file `detection-engineering/suricata_check.py` writes,
    which also carries the capture name so `--file` can be omitted.
    """
    with open(path) as f:
        text = f.read().strip()

    capture = None
    try:
        payload = json.loads(text) if text else []
    except json.JSONDecodeError:
        payload = [json.loads(line) for line in text.splitlines() if line.strip()]

    alerts = []
    if isinstance(payload, dict):
        capture = payload.get("capture")
        payload = payload.get("alerts", [])

    for record in payload:
        if not isinstance(record, dict):
            continue
        inner = record.get("alert") if isinstance(record.get("alert"), dict) else None
        if inner is None and record.get("event_type") not in (None, "alert"):
            continue
        source = inner or record
        alerts.append(
            {
                "sid": source.get("signature_id", source.get("sid")),
                "signature": source.get("signature"),
                "timestamp": record.get("timestamp"),
            }
        )
    return alerts, capture


def derive_detections(stats, alerts):
    """
    Name what triggered this report, in keys the triage loop can join on.

    IDS alerts are keyed by SID; the DPI finding is keyed by the operation class.
    The same keys appear in the report, in the audit log and in dispositions, so
    "what fired" and "what an analyst decided" can be joined without guessing.
    """
    detections = []
    for alert in alerts:
        key = f"sid:{alert['sid']}"
        if key not in detections:
            detections.append(key)
    detections.append(f"dpi:{operation_class(stats)}")
    return detections


def normalise_timestamp(value):
    """Render a Suricata timestamp as a second-resolution UTC string."""
    if not value:
        return "unknown"
    try:
        return parse_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return str(value)


def render_trigger_section(context, file_name):
    """Render the section that says what caused this report to exist."""
    alerts = context["alerts"]
    if alerts:
        rows = "\n".join(
            f"| {alert['sid']} | {alert['signature']} | "
            f"{normalise_timestamp(alert['timestamp'])} |"
            for alert in alerts
        )
        evidence = context.get("evidence") or "not recorded"
        plural = "alert" if len(alerts) == 1 else "alerts"
        return (
            f"This report was triggered by {len(alerts)} IDS {plural}. Evidence: "
            f"`{evidence}`.\n\n"
            "| SID | Signature | Event time |\n"
            "| :--- | :--- | :--- |\n"
            f"{rows}"
        )
    if context["trigger"] == "forced":
        return (
            "No IDS alert triggered this report. It was forced with "
            "`--trigger-alert`, so it reflects the DPI profile below rather than "
            "a detection."
        )
    return (
        "No IDS alert triggered this report. It was generated from the DPI "
        f"profile because the capture contains a `{context['operation']}` "
        "finding, and nothing in this repository alerts on it."
    )


def render_change_window(context):
    """Render the change-window status for the report."""
    window = context.get("window")
    if not window:
        return (
            "No approved change window covers the event "
            "(`automation/change_windows.json`)."
        )
    return (
        f"Covered by `{window['id']}` — {window.get('reason', 'no reason recorded')} "
        f"({window.get('owner', 'unowned')}, {window['start']} to {window['end']}). "
        f"Ticket: {window.get('ticket', 'none')}."
    )


def build_report_context(stats, file_name, alerts=None, evidence=None, forced=False):
    """Resolve everything a report needs: assets, severity, window, detections."""
    inventory = load_inventory()
    alerts = alerts or []

    target_ip = stats.get("primary_target") or "Unknown"
    # Prefer the source of the control operations: that is the asset an analyst
    # has to triage, and it is not necessarily the busiest talker in the capture.
    write_sources = stats.get("write_sources") or []
    source_ip = (write_sources[0] if write_sources else stats.get("primary_source")) or "Unknown"

    target_ctx = inventory.get(
        target_ip,
        {
            "name": "Unknown Asset",
            "zone": "Unknown",
            "type": "Unknown",
            "criticality": "Unknown",
            "owner": "Unknown",
        },
    )
    source_ctx = inventory.get(source_ip, {"name": "Unknown Asset", "zone": "Unknown"})

    # The write allowlist lives in the asset model rather than in a rule, so a
    # new or unknown writer is visible instead of silently trusted.
    if source_ip not in inventory:
        authorized = "Unknown (source is not in the asset inventory)"
    elif inventory[source_ip].get("control_writer"):
        authorized = "Yes (allowlisted control writer)"
    else:
        authorized = "No (asset is not an allowlisted control writer)"

    operation = operation_class(stats)
    # The window is matched on the asset the operation was aimed at and on the
    # time the operation happened, read from the capture.
    window = find_change_window(
        target_ip,
        operation,
        stats.get("first_write_event") or stats.get("first_event"),
    )
    criticality = target_ctx["criticality"]
    severity = severity_for(operation, criticality, window)

    alert_message, attack_type = OPERATION_LABELS[operation]
    if window and operation in WINDOW_LABELS:
        alert_message, attack_type = WINDOW_LABELS[operation]

    if alerts:
        trigger = "alert"
    elif forced:
        trigger = "forced"
    else:
        trigger = "profiler"

    return {
        "file_name": file_name,
        "alerts": alerts,
        "evidence": evidence,
        "trigger": trigger,
        "operation": operation,
        "window": window,
        "severity": severity,
        "severity_basis": severity_basis(operation, criticality, window),
        "detections": derive_detections(stats, alerts),
        "alert_message": alert_message,
        "attack_type": attack_type,
        "source_ip": source_ip,
        "source_ctx": source_ctx,
        "target_ip": target_ip,
        "target_ctx": target_ctx,
        "authorized": authorized,
    }


def render_mitre_rows(stats):
    """Render the ATT&CK for ICS table rows from the techniques actually asserted."""
    tags = stats.get("mitre_tags", [])
    if not tags:
        return "| — | — | No ATT&CK for ICS technique is asserted for this traffic. |"
    return "\n".join(
        f"| {tag} | {MITRE_TECHNIQUES[tag][0]} | {MITRE_TECHNIQUES[tag][1]} |"
        for tag in tags
    )


def generate_incident_report(stats, file_name, sha256, context=None):
    """Generate a NIST-aligned incident report enriched with asset context."""
    if context is None:
        context = build_report_context(stats, file_name)

    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d-%H%M%S")
    # The capture name is part of the report name: two captures ingested in the
    # same second would otherwise collide and overwrite each other, and the name
    # should say which evidence produced the report.
    stem = os.path.splitext(file_name)[0]
    report_path = os.path.join(REPORT_OUTPUT_DIR, f"Incident_Report_{timestamp}_{stem}.md")

    first_event = stats.get("first_event")
    last_event = stats.get("last_event")
    if first_event and last_event:
        event_date = first_event.strftime("%B %d, %Y")
        event_window = (
            f"{first_event.strftime('%Y-%m-%d %H:%M:%S')} – "
            f"{last_event.strftime('%H:%M:%S')}"
        )
    else:
        event_date = "an undetermined date"
        event_window = "not derived (no Modbus traffic in the capture)"

    target_ctx = context["target_ctx"]
    source_ctx = context["source_ctx"]
    detections = ", ".join(f"`{key}`" for key in context["detections"])

    replacements = {
        "{{ ALERT_MESSAGE }}": context["alert_message"],
        "{{ TIMESTAMP_ID }}": timestamp,
        "{{ INCIDENT_LEAD }}": "Liam Carvajal (Automated)",
        "{{ REPORT_DATE }}": now.strftime("%B %d, %Y"),
        "{{ REPORT_TIME }}": now.strftime("%H:%M:%S"),
        "{{ REPORT_TIMESTAMP }}": now.strftime("%Y-%m-%d %H:%M:%S"),
        "{{ EVENT_DATE }}": event_date,
        "{{ EVENT_WINDOW }}": event_window,
        "{{ SEVERITY }}": context["severity"],
        "{{ SEVERITY_BASIS }}": context["severity_basis"],
        "{{ ATTACK_TYPE }}": context["attack_type"],
        "{{ CHANGE_WINDOW }}": render_change_window(context),
        "{{ TRIGGER_SECTION }}": render_trigger_section(context, file_name),
        "{{ DETECTIONS }}": detections,
        "{{ CAPTURE_NAME }}": file_name,
        "{{ TARGET_ASSET }}": target_ctx["name"],
        "{{ TARGET_IP }}": context["target_ip"],
        "{{ TARGET_ZONE }}": target_ctx["zone"],
        "{{ SOURCE_IP }}": context["source_ip"],
        "{{ SOURCE_ASSET }}": source_ctx["name"],
        "{{ SOURCE_ZONE }}": source_ctx["zone"],
        "{{ SOURCE_AUTHORIZED }}": context["authorized"],
        "{{ SHA256 }}": sha256,
        "{{ FUNC_CODES }}": ", ".join(stats["func_codes"]),
        "{{ REQUEST_COUNT }}": str(stats["modbus_requests"]),
        "{{ WRITE_COUNT }}": str(stats["writes"]),
        "{{ CRITICAL_WRITE_COUNT }}": str(stats["critical_writes"]),
        "{{ MITRE_ROWS }}": render_mitre_rows(stats),
        "{{ TARGET_TYPE }}": target_ctx["type"],
        "{{ TARGET_CRITICALITY }}": target_ctx["criticality"],
        "{{ TARGET_OWNER }}": target_ctx["owner"],
    }

    try:
        with open(REPORT_TEMPLATE) as f:
            content = f.read()

        for key, val in replacements.items():
            content = content.replace(key, val)

        with open(report_path, "w") as f:
            f.write(content)

        logger.info(
            f"Forensic report generated: {os.path.relpath(report_path, PROJECT_DIR)}"
        )
        return report_path
    except OSError as e:
        logger.error(f"Report generation failed: {e}")
        return None


def ingested_hashes():
    """SHA-256 of every capture the audit log records as successfully ingested.

    The audit log is already the record of what was ingested, so the watcher's
    deduplication reads it rather than keeping a second store that could drift
    from it.
    """
    seen = set()
    if not os.path.exists(AUDIT_LOG):
        return seen
    with open(AUDIT_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(entry.get("status", "")).startswith("SUCCESS") and entry.get("sha256"):
                seen.add(entry["sha256"])
    return seen


def watch_pass(directory, known, sizes, sanitize=False):
    """
    One pass over a watched directory. Returns the updated known hashes.

    Split out from the loop so the behaviour can be tested: a capture is
    ingested the first time its size is stable and its hash is not already in the
    audit log, and every later pass skips it.
    """
    for name in sorted(os.listdir(directory)):
        if not name.endswith((".pcap", ".pcapng")):
            continue
        path = os.path.join(directory, name)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if sizes.get(name) != size:
            # First sight, or the writer has not finished: look again next pass.
            sizes[name] = size
            continue
        digest = calculate_sha256(path)
        if digest is None:
            continue
        if digest in known:
            logger.info(f"Already ingested, skipping: {name}")
            continue
        logger.info(f"New capture: {name}")
        ingest_pcap(name, sanitize=sanitize, source_dir=directory)
        known = ingested_hashes()
    return known


def watch_capture_dir(directory, interval=5.0, sanitize=False):
    """
    Ingest captures as they appear in a directory, each one exactly once.

    This is the deployed shape: Malcolm rotates live captures into a directory
    and this watches it. A capture whose SHA-256 is already in the audit log is
    skipped, so restarting the service does not re-ingest the estate.
    """
    logger.info(f"Watching {directory} for captures every {interval:g}s.")
    known = ingested_hashes()
    sizes = {}
    try:
        while True:
            known = watch_pass(directory, known, sizes, sanitize=sanitize)
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Watch stopped.")
        return 0


def ingest_pcap(file_name, trigger_report=False, sanitize=False, alerts_path=None,
                source_dir=None):
    """
    Run the ingestion pipeline: hash -> DPI -> report -> [sanitize] -> ingest.

    DPI and context enrichment always run against the original evidence;
    sanitization only ever affects the copy that is shipped to Malcolm. An
    alert file turns the run into an alert-triggered triage: the report names the
    alert that caused it instead of the profiler noticing a write.

    ``source_dir`` defaults to the repository's ``pcaps/`` and is overridden by
    watch mode, where the capture arrives in the directory being watched.
    """
    src = os.path.join(source_dir or PCAP_SOURCE, file_name)
    if not os.path.exists(src):
        logger.error(f"Source file not found: {src}")
        return False

    alerts, evidence_capture = [], None
    evidence_name = None
    if alerts_path:
        try:
            alerts, evidence_capture = load_alerts(alerts_path)
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Could not read alerts from {alerts_path}: {e}")
            return False
        if not alerts:
            logger.warning(f"No alert records in {alerts_path}.")
        # An evidence file names the capture it was produced from. If that does
        # not match, the wiring is wrong and the report would describe the wrong
        # evidence, so stop rather than guess.
        if evidence_capture and evidence_capture != file_name:
            logger.error(
                f"Alert evidence is for {evidence_capture}, but {file_name} was given."
            )
            return False
        evidence_name = os.path.relpath(alerts_path, PROJECT_DIR)

    file_size = os.path.getsize(src)
    sha256 = calculate_sha256(src)
    if not sha256:
        update_audit_log(file_name, "N/A", "FAILED (hash error)", file_size)
        return False

    stats = analyze_pcap_dpi(src)
    if stats is None:
        update_audit_log(file_name, sha256, "FAILED (DPI error)", file_size)
        return False

    context = build_report_context(
        stats, file_name, alerts=alerts, evidence=evidence_name, forced=trigger_report
    )
    logger.info(f"Trigger: {context['trigger']} | detections: {', '.join(context['detections'])}")
    logger.info(f"Severity {context['severity']} — {context['severity_basis']}")

    if alerts or trigger_report or stats.get("writes", 0) > 0:
        generate_incident_report(stats, file_name, sha256, context)

    work_file = src
    sanitized_sha256 = None
    if sanitize:
        sanitized_path = os.path.join(SANITIZE_DIR, file_name)
        if sanitize_pcap(src, sanitized_path):
            work_file = sanitized_path
            sanitized_sha256 = calculate_sha256(sanitized_path)

    try:
        destination = os.path.join(MALCOLM_PCAP_DIR, file_name)
        if os.path.exists(MALCOLM_PCAP_DIR):
            if os.path.abspath(work_file) == os.path.abspath(destination):
                # Watch mode: the capture is already in the directory Malcolm
                # monitors, so there is nothing to ship.
                logger.info(f"Already in the Malcolm directory: {file_name}")
            else:
                shutil.copy2(work_file, destination)
                logger.info(f"Pipeline success: {file_name} ingested to Malcolm.")
        else:
            logger.info(
                f"Simulation mode: {file_name} processed successfully "
                f"({MALCOLM_PCAP_DIR} not present)."
            )

        audit_fields = {
            "trigger": context["trigger"],
            "detections": context["detections"],
        }
        if alerts:
            audit_fields["alert_sids"] = [alert["sid"] for alert in alerts]
        if sanitized_sha256:
            audit_fields["sanitized_sha256"] = sanitized_sha256
        update_audit_log(file_name, sha256, "SUCCESS", file_size, **audit_fields)
        return True
    except OSError as e:
        logger.error(f"Ingestion failed for {file_name}: {e}")
        update_audit_log(file_name, sha256, f"FAILED ({e})", file_size)
        return False


def main():
    """Parse arguments and run the ingestion pipeline."""
    parser = argparse.ArgumentParser(description="Industrial NDR Orchestration Pipeline")
    parser.add_argument("--file", help="PCAP file name in pcaps/ directory")
    parser.add_argument("--all", action="store_true", help="Process all PCAPs in directory")
    parser.add_argument("--trigger-alert", action="store_true", help="Force report generation")
    parser.add_argument("--sanitize", action="store_true",
                        help="Anonymize evidence before ingestion")
    parser.add_argument(
        "--alerts",
        help="Alert file that triggered this triage: a Suricata eve.json, or the "
             "evidence file written by detection-engineering/suricata_check.py",
    )
    parser.add_argument(
        "--watch",
        metavar="DIR",
        help="Run as a service: ingest captures that appear in DIR, once each. "
             "This is the deployed shape, pointed at Malcolm's PCAP directory.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds between passes in --watch mode (default: 5)",
    )

    args = parser.parse_args()

    if args.watch:
        if args.file or args.all or args.alerts:
            parser.error("--watch runs the service; it cannot be combined with "
                         "--file, --all or --alerts")
            return 1
        if not os.path.isdir(args.watch):
            parser.error(f"--watch directory does not exist: {args.watch}")
            return 1
        return watch_capture_dir(args.watch, interval=args.interval, sanitize=args.sanitize)

    if args.alerts and args.all:
        parser.error("--alerts triggers one triage; it cannot be combined with --all")
        return

    if args.alerts:
        # The evidence file names the capture, so --file is optional with it.
        if not args.file:
            _, capture = load_alerts(args.alerts)
            if not capture:
                parser.error("--alerts without --file needs an evidence file naming the capture")
                return
            args.file = capture
        ingest_pcap(
            args.file,
            trigger_report=args.trigger_alert,
            sanitize=args.sanitize,
            alerts_path=args.alerts,
        )
    elif args.all:
        files = [f for f in sorted(os.listdir(PCAP_SOURCE)) if f.endswith((".pcap", ".pcapng"))]
        for f in files:
            ingest_pcap(f, trigger_report=args.trigger_alert, sanitize=args.sanitize)
    elif args.file:
        ingest_pcap(args.file, trigger_report=args.trigger_alert, sanitize=args.sanitize)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
