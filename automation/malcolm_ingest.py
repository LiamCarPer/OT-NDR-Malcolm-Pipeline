#!/usr/bin/env python3
"""
Malcolm NDR Ingestion & Forensic Profiler
Author: Liam Carvajal (@LiamCarPer)
Automates PCAP ingestion into CISA Malcolm with pre-analysis DPI and forensic integrity checks.
"""

import os
import shutil
import time
import argparse
import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime

from datetime import datetime

# --- System Config ---
MALCOLM_PCAP_DIR = os.environ.get("MALCOLM_PCAP_DIR", "/opt/Malcolm/pcap")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
PCAP_SOURCE = os.path.join(PROJECT_DIR, "pcaps")
AUDIT_LOG = os.path.join(SCRIPT_DIR, "ingest_audit.log")

def log(msg, level="INFO"):
    """Custom logger with security-focused tags."""
    tags = {
        "INFO": "[\033[94mINFO\033[0m]",
        "WARNING": "[\033[93mWARN\033[0m]",
        "ERROR": "[\033[91mFAIL\033[0m]",
        "CRITICAL": "[\033[91m\033[1mALERT\033[0m]",
        "FORENSIC": "[\033[92mHASH\033[0m]"
    }
    tag = tags.get(level, f"[{level}]")
    print(f"{tag} {msg}")

def validate_pcap(file_path):
    """Basic validation to ensure the file is a PCAP."""
    if not os.path.exists(file_path):
        log(f"File not found: {file_path}", "ERROR")
        return False
    
    if not file_path.endswith(('.pcap', '.pcapng')):
        log(f"Invalid file extension: {file_path}. Must be .pcap or .pcapng", "WARNING")
        return False
    
    # Check if file is not empty
    if os.path.getsize(file_path) == 0:
        log(f"File is empty: {file_path}", "ERROR")
        return False
        
    return True

def calculate_sha256(file_path):
    """Calculates SHA-256 hash of a file for forensic integrity."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read in chunks to avoid memory issues with large PCAPs
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        log(f"Hash calculation failed: {str(e)}", "ERROR")
        return None

def update_audit_log(file_name, sha256, status, size):
    """Updates the forensic audit log with ingestion details."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file": file_name,
        "sha256": sha256,
        "size_bytes": size,
        "status": status
    }
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        log(f"Failed to update audit log: {str(e)}", "ERROR")

def analyze_pcap_dpi(file_path):
    """Performs deep packet inspection to profile OT traffic."""
    log(f"Starting DPI Analysis for {os.path.basename(file_path)}...")
    
    try:
        # Pass 1: Extract IPs and Modbus Function Codes
        # -Y mbtcp filters for Modbus traffic
        cmd = [
            "tshark", "-r", file_path, 
            "-T", "fields", 
            "-e", "ip.src", "-e", "ip.dst", "-e", "modbus.func_code",
            "-Y", "mbtcp", "-c", "1000" # Limit to first 1000 packets for speed
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        lines = result.stdout.strip().split("\n")
        if not lines or lines == ['']:
            log("No Modbus traffic detected in this capture.", "WARNING")
            return

        src_ips = []
        dst_ips = []
        func_codes = []
        
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 2:
                src_ips.append(parts[0])
                dst_ips.append(parts[1])
            if len(parts) >= 3 and parts[2]:
                # Tshark can return multiple codes for one packet if nested, take the first
                func_codes.append(parts[2].split(",")[0])

        # Summary Statistics
        unique_assets = set(src_ips) | set(dst_ips)
        code_counts = Counter(func_codes)
        
        log("--- Industrial Traffic Profile ---")
        log(f"Unique OT Assets Identified: {len(unique_assets)}")
        for ip in sorted(list(unique_assets))[:5]: # Show top 5
            log(f"  - Asset: {ip}")
        
        log(f"Modbus Commands Detected: {len(func_codes)}")
        
        # OT Security Context: Flagging control operations (Write vs Read)
        # Codes 5, 6, 15, 16 indicate state manipulation or setpoint changes.
        reads = sum(count for code, count in code_counts.items() if code in ['1', '2', '3', '4'])
        writes = sum(count for code, count in code_counts.items() if code in ['5', '6', '15', '16'])
        
        log(f"  - Monitoring (Reads): {reads}")
        if writes > 0:
            log(f"Security Alert: {writes} Control Operations (Writes) detected!", "CRITICAL")
        else:
            log("No control operations detected (Baseline traffic).")
        
        log("--- Analysis Complete ---")

    except Exception as e:
        log(f"DPI Analysis failed: {str(e)}", "ERROR")

def ingest_to_malcolm(file_name):
    """Copies the PCAP to Malcolm's monitored directory for processing."""
    src = os.path.join(PCAP_SOURCE, file_name)
    dst = os.path.join(MALCOLM_PCAP_DIR, file_name)
    
    if not validate_pcap(src):
        return False
    
    file_size = os.path.getsize(src)
    sha256 = calculate_sha256(src)
    
    if not sha256:
        update_audit_log(file_name, "N/A", "FAILED (Hash Error)", file_size)
        return False

    # Perform DPI Analysis
    analyze_pcap_dpi(src)

    try:
        log(f"Starting ingestion for {file_name}...")
        log(f"Forensic Hash (SHA-256): {sha256}")
        shutil.copy2(src, dst)
        
        log(f"Successfully moved {file_name} to Malcolm ingestion engine.")
        log(f"Processing started. Check dashboards at https://localhost/dashboards")
        
        update_audit_log(file_name, sha256, "SUCCESS", file_size)
        return True
    except Exception as e:
        log(f"Failed to ingest {file_name}: {str(e)}", "ERROR")
        update_audit_log(file_name, sha256, f"FAILED ({str(e)})", file_size)
        return False

def main():
    parser = argparse.ArgumentParser(description="Automate PCAP ingestion into CISA Malcolm.")
    parser.add_argument("--file", help="Name of the PCAP file in the project pcaps/ folder")
    parser.add_argument("--all", action="store_true", help="Ingest all PCAPs in the project pcaps/ folder")
    
    args = parser.parse_args()
    
    if not os.path.exists(MALCOLM_PCAP_DIR):
        log(f"Malcolm PCAP directory not found: {MALCOLM_PCAP_DIR}", "CRITICAL")
        return

    if args.all:
        files = [f for f in os.listdir(PCAP_SOURCE) if f.endswith(('.pcap', '.pcapng'))]
        for f in files:
            ingest_to_malcolm(f)
    elif args.file:
        ingest_to_malcolm(args.file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
