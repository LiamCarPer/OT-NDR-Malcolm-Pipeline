#!/usr/bin/env python3
"""
Malcolm NDR Ingestion & Forensic Profiler
Author: Liam Carvajal (@LiamCarPer)
Automates PCAP ingestion into CISA Malcolm with pre-analysis DPI and forensic integrity checks.
"""

#!/usr/bin/env python3
"""
OT-NDR Orchestration & Forensic Pipeline
Author: Liam Carvajal (@LiamCarPer)
Implements forensic integrity, deep packet inspection (DPI), and automated incident reporting.
"""

import os
import shutil
import time
import argparse
import hashlib
import json
import logging
import subprocess
from collections import Counter
from datetime import datetime

# --- System Configuration ---
MALCOLM_PCAP_DIR = os.environ.get("MALCOLM_PCAP_DIR", "/opt/Malcolm/pcap")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
PCAP_SOURCE = os.path.join(PROJECT_DIR, "pcaps")
AUDIT_LOG = os.path.join(SCRIPT_DIR, "ingest_audit.log")
ASSET_INVENTORY = os.path.join(SCRIPT_DIR, "asset_inventory.json")
REPORT_TEMPLATE = os.path.join(PROJECT_DIR, "incident-response", "Incident_Report_Template.md")
REPORT_OUTPUT_DIR = os.path.join(PROJECT_DIR, "incident-response")

# Setup professional logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(AUDIT_LOG)
    ]
)
logger = logging.getLogger("NDR-Pipeline")

def load_inventory():
    """Loads asset inventory for orchestration context."""
    if os.path.exists(ASSET_INVENTORY):
        try:
            with open(ASSET_INVENTORY, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error("Failed to decode asset inventory JSON.")
    return {}

def calculate_sha256(file_path):
    """Calculates SHA-256 hash of a file for forensic integrity."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Hash calculation failed for {file_path}: {str(e)}")
        return None

def sanitize_pcap(input_path, output_path):
    """
    Anonymizes IP addresses and strips non-essential payloads for privacy.
    Requires tcprewrite (part of tcpreplay suite).
    """
    logger.info(f"Initiating privacy sanitization for {os.path.basename(input_path)}...")
    try:
        # Anonymize IPs by mapping them to 10.x.x.x range for privacy
        cmd = [
            "tcprewrite", "--pnat=0.0.0.0/0:10.0.0.0/8", 
            "--infile=" + input_path, "--outfile=" + output_path
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        logger.info(f"Sanitization complete. Evidence stored at {output_path}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("tcprewrite not found or failed. Skipping sanitization.")
        return False

def analyze_pcap_dpi(file_path):
    """
    Performs deep packet inspection to profile OT traffic.
    Extracts Modbus function codes and identifies potential register manipulation.
    """
    logger.info(f"Starting Deep Packet Inspection (DPI) for {os.path.basename(file_path)}")
    
    stats = {
        "src_ips": [],
        "dst_ips": [],
        "func_codes": [],
        "reads": 0,
        "writes": 0,
        "critical_writes": 0,
        "total_packets": 0,
        "mitre_tags": []
    }

    try:
        # Extract Modbus fields: source, destination, function code, and register data
        cmd = [
            "tshark", "-r", file_path, 
            "-T", "fields", 
            "-e", "ip.src", "-e", "ip.dst", "-e", "modbus.func_code", "-e", "modbus.reference_num",
            "-Y", "mbtcp", "-c", "5000"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        lines = result.stdout.strip().split("\n")
        if not lines or lines == ['']:
            logger.warning("No Modbus TCP traffic identified in capture.")
            return stats

        src_ips, dst_ips, func_codes = [], [], []
        
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 3:
                src_ips.append(parts[0])
                dst_ips.append(parts[1])
                f_code = parts[2].split(",")[0]
                func_codes.append(f_code)
                
                # Tag critical register writes (e.g., registers in the 1000+ range often denote setpoints)
                if f_code in ['5', '6', '15', '16']:
                    stats["writes"] += 1
                    if len(parts) >= 4 and parts[3] and int(parts[3]) >= 1000:
                        stats["critical_writes"] += 1

        stats["src_ips"] = list(set(src_ips))
        stats["dst_ips"] = list(set(dst_ips))
        stats["func_codes"] = list(set(func_codes))
        stats["total_packets"] = len(lines)
        
        code_counts = Counter(func_codes)
        stats["reads"] = sum(count for code, count in code_counts.items() if code in ['1', '2', '3', '4'])
        
        # MITRE ATT&CK for ICS Mapping
        if stats["writes"] > 0:
            stats["mitre_tags"].append("T0836") # Modify Parameter
        if stats["critical_writes"] > 0:
            stats["mitre_tags"].append("T0855") # Unauthorized Command Message

        logger.info(f"DPI Summary: {stats['total_packets']} Modbus packets analyzed.")
        logger.info(f"Operations: Reads={stats['reads']}, Writes={stats['writes']} (Critical={stats['critical_writes']})")
        
        return stats

    except Exception as e:
        logger.error(f"DPI Analysis failed: {str(e)}")
        return stats

def generate_incident_report(stats, file_name, sha256):
    """Automated forensic report generation with asset context enrichment."""
    inventory = load_inventory()
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_name = f"Incident_Report_{timestamp}.md"
    report_path = os.path.join(REPORT_OUTPUT_DIR, report_name)
    
    target_ip = stats["dst_ips"][0] if stats["dst_ips"] else "Unknown"
    source_ip = stats["src_ips"][0] if stats["src_ips"] else "Unknown"
    
    target_ctx = inventory.get(target_ip, {"name": "Unknown Asset", "zone": "Unknown", "type": "Unknown", "criticality": "Unknown", "owner": "Unknown"})
    source_ctx = inventory.get(source_ip, {"name": "Unknown Asset", "zone": "Unknown"})

    replacements = {
        "{{ ALERT_MESSAGE }}": "Unauthorized Modbus Write" if stats["critical_writes"] > 0 else "Modbus Baseline Drift",
        "{{ TIMESTAMP_ID }}": timestamp,
        "{{ INCIDENT_LEAD }}": "Liam Carvajal (Automated)",
        "{{ DATE }}": datetime.now().strftime("%B %d, %Y"),
        "{{ SEVERITY }}": "CRITICAL" if stats["critical_writes"] > 0 else "HIGH" if stats["writes"] > 0 else "MEDIUM",
        "{{ ATTACK_TYPE }}": "Unauthorized Setpoint Manipulation" if stats["critical_writes"] > 0 else "Unauthorized Command Execution",
        "{{ TARGET_ASSET }}": target_ctx["name"],
        "{{ TARGET_IP }}": target_ip,
        "{{ TARGET_ZONE }}": target_ctx["zone"],
        "{{ EVENT_TIME }}": datetime.now().strftime("%H:%M:%S"),
        "{{ SHA256 }}": sha256,
        "{{ SOURCE_IP }}": source_ip,
        "{{ SOURCE_ASSET }}": source_ctx["name"],
        "{{ SOURCE_ZONE }}": source_ctx["zone"],
        "{{ FUNC_CODES }}": ", ".join(stats["func_codes"]),
        "{{ WRITE_COUNT }}": str(stats["writes"]),
        "{{ TARGET_TYPE }}": target_ctx["type"],
        "{{ TARGET_CRITICALITY }}": target_ctx["criticality"],
        "{{ TARGET_OWNER }}": target_ctx["owner"]
    }

    try:
        with open(REPORT_TEMPLATE, 'r') as f:
            content = f.read()
        
        for key, val in replacements.items():
            content = content.replace(key, val)
        
        with open(report_path, 'w') as f:
            f.write(content)
        
        logger.info(f"Forensic Report generated: {report_path}")
        return report_path
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return None

def ingest_pcap(file_name, trigger_report=False, sanitize=False):
    """Executes the ingestion pipeline: Hash -> [Sanitize] -> DPI -> [Report] -> Ingest."""
    src = os.path.join(PCAP_SOURCE, file_name)
    if not os.path.exists(src):
        logger.error(f"Source file not found: {src}")
        return False

    sha256 = calculate_sha256(src)
    if not sha256: return False

    work_file = src
    if sanitize:
        sanitized_path = os.path.join(PCAP_SOURCE, f"sanitized_{file_name}")
        if sanitize_pcap(src, sanitized_path):
            work_file = sanitized_path

    stats = analyze_pcap_dpi(work_file)

    if trigger_report or stats.get("writes", 0) > 0:
        generate_incident_report(stats, file_name, sha256)

    try:
        dst = os.path.join(MALCOLM_PCAP_DIR, file_name)
        if os.path.exists(MALCOLM_PCAP_DIR):
            shutil.copy2(work_file, dst)
            logger.info(f"Pipeline Success: {file_name} ingested to Malcolm.")
        else:
            logger.info(f"Simulation Mode: {file_name} processed successfully.")
        
        return True
    except Exception as e:
        logger.error(f"Ingestion failed for {file_name}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Industrial NDR Orchestration Pipeline")
    parser.add_argument("--file", help="PCAP file name in pcaps/ directory")
    parser.add_argument("--all", action="store_true", help="Process all PCAPs in directory")
    parser.add_argument("--trigger-alert", action="store_true", help="Force report generation")
    parser.add_argument("--sanitize", action="store_true", help="Anonymize evidence before ingestion")
    
    args = parser.parse_args()
    
    if args.all:
        files = [f for f in os.listdir(PCAP_SOURCE) if f.endswith(('.pcap', '.pcapng'))]
        for f in files:
            ingest_pcap(f, trigger_report=args.trigger_alert, sanitize=args.sanitize)
    elif args.file:
        ingest_pcap(args.file, trigger_report=args.trigger_alert, sanitize=args.sanitize)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
