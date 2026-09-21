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
REPORT_TEMPLATE = os.path.join(PROJECT_DIR, "incident-response", "Incident_Report_Template.md")
REPORT_OUTPUT_DIR = os.path.join(PROJECT_DIR, "incident-response")
SANITIZE_DIR = os.path.join(tempfile.gettempdir(), "ot-ndr-sanitized")

# --- Modbus/TCP semantics ---
# Function codes 1-4 are read operations, 5/6/15/16 write to the device, and
# registers at or above 1000 are treated as setpoint-class in this lab.
READ_FUNCTIONS = {"1", "2", "3", "4"}
WRITE_FUNCTIONS = {"5", "6", "15", "16"}
SETPOINT_REGISTER_FLOOR = 1000

# ATT&CK for ICS techniques this DPI heuristic can assert, and the evidence
# required for each one. Techniques are never hardcoded into a report: they are
# derived from the observed operations, so a capture with no control writes
# cannot claim a write technique.
MITRE_TECHNIQUES = {
    "T0836": ("Modify Parameter", "Modbus write commands observed."),
    "T0855": (
        "Unauthorized Command Message",
        "Write to a setpoint-class register (>= 1000).",
    ),
    "T0888": (
        "Remote System Discovery",
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
    truncated. Returns None if the analysis could not run, so the caller fails
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

    src_ips, dst_ips, func_codes, references = [], [], [], []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2]:
            continue
        src_ips.append(parts[0])
        dst_ips.append(parts[1])
        func_codes.append(parts[2].split(",")[0])
        references.append(parts[3] if len(parts) > 3 else "")

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

    tags = []
    if stats["writes"]:
        tags.append("T0836")
    if stats["critical_writes"]:
        tags.append("T0855")
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


def render_mitre_rows(stats):
    """Render the ATT&CK for ICS table rows from the techniques actually asserted."""
    tags = stats.get("mitre_tags", [])
    if not tags:
        return "| — | — | No ATT&CK for ICS technique is asserted for this traffic. |"
    return "\n".join(
        f"| {tag} | {MITRE_TECHNIQUES[tag][0]} | {MITRE_TECHNIQUES[tag][1]} |"
        for tag in tags
    )


def generate_incident_report(stats, file_name, sha256):
    """Generate a NIST-aligned incident report enriched with asset context."""
    inventory = load_inventory()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    # The capture name is part of the report name: two captures ingested in the
    # same second would otherwise collide and overwrite each other, and the name
    # should say which evidence produced the report.
    stem = os.path.splitext(file_name)[0]
    report_name = f"Incident_Report_{timestamp}_{stem}.md"
    report_path = os.path.join(REPORT_OUTPUT_DIR, report_name)

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

    if stats["critical_writes"]:
        alert_message = "Unauthorized Modbus Setpoint Write"
        attack_type = "Unauthorized Setpoint Manipulation"
        severity = "CRITICAL"
    elif stats["writes"]:
        alert_message = "Unauthorized Modbus Write"
        attack_type = "Unauthorized Command Execution"
        severity = "HIGH"
    else:
        alert_message = "Modbus Baseline Drift"
        attack_type = "Reconnaissance / Baseline Drift"
        severity = "MEDIUM"

    now = datetime.now(timezone.utc)
    replacements = {
        "{{ ALERT_MESSAGE }}": alert_message,
        "{{ TIMESTAMP_ID }}": timestamp,
        "{{ INCIDENT_LEAD }}": "Liam Carvajal (Automated)",
        "{{ DATE }}": now.strftime("%B %d, %Y"),
        "{{ EVENT_TIME }}": now.strftime("%H:%M:%S"),
        "{{ SEVERITY }}": severity,
        "{{ ATTACK_TYPE }}": attack_type,
        "{{ TARGET_ASSET }}": target_ctx["name"],
        "{{ TARGET_IP }}": target_ip,
        "{{ TARGET_ZONE }}": target_ctx["zone"],
        "{{ SOURCE_IP }}": source_ip,
        "{{ SOURCE_ASSET }}": source_ctx["name"],
        "{{ SOURCE_ZONE }}": source_ctx["zone"],
        "{{ SOURCE_AUTHORIZED }}": authorized,
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


def ingest_pcap(file_name, trigger_report=False, sanitize=False):
    """
    Run the ingestion pipeline: hash -> DPI -> report -> [sanitize] -> ingest.

    DPI and context enrichment always run against the original evidence;
    sanitization only ever affects the copy that is shipped to Malcolm.
    """
    src = os.path.join(PCAP_SOURCE, file_name)
    if not os.path.exists(src):
        logger.error(f"Source file not found: {src}")
        return False

    file_size = os.path.getsize(src)
    sha256 = calculate_sha256(src)
    if not sha256:
        update_audit_log(file_name, "N/A", "FAILED (hash error)", file_size)
        return False

    stats = analyze_pcap_dpi(src)
    if stats is None:
        update_audit_log(file_name, sha256, "FAILED (DPI error)", file_size)
        return False

    if trigger_report or stats.get("writes", 0) > 0:
        generate_incident_report(stats, file_name, sha256)

    work_file = src
    sanitized_sha256 = None
    if sanitize:
        sanitized_path = os.path.join(SANITIZE_DIR, file_name)
        if sanitize_pcap(src, sanitized_path):
            work_file = sanitized_path
            sanitized_sha256 = calculate_sha256(sanitized_path)

    try:
        if os.path.exists(MALCOLM_PCAP_DIR):
            shutil.copy2(work_file, os.path.join(MALCOLM_PCAP_DIR, file_name))
            logger.info(f"Pipeline success: {file_name} ingested to Malcolm.")
        else:
            logger.info(
                f"Simulation mode: {file_name} processed successfully "
                f"({MALCOLM_PCAP_DIR} not present)."
            )

        audit_fields = {"sanitized_sha256": sanitized_sha256} if sanitized_sha256 else {}
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

    args = parser.parse_args()

    if args.all:
        files = [f for f in sorted(os.listdir(PCAP_SOURCE)) if f.endswith((".pcap", ".pcapng"))]
        for f in files:
            ingest_pcap(f, trigger_report=args.trigger_alert, sanitize=args.sanitize)
    elif args.file:
        ingest_pcap(args.file, trigger_report=args.trigger_alert, sanitize=args.sanitize)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
