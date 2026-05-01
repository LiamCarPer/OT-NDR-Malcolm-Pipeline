#!/usr/bin/env python3
"""
Malcolm NDR Pipeline - Automated Ingestion Script (DevSecOps)
This script simulates a DevSecOps pipeline step by automatically 
validating and ingesting PCAP data into the Malcolm analyzer.
"""

import os
import shutil
import time
import argparse
from datetime import datetime

try:
    from dotenv import load_dotenv
    # Load environment variables from a .env file if present
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))
except ImportError:
    pass

# --- Configuration ---
# Allow Malcolm PCAP dir to be configured via environment variable, defaulting to a standard path
MALCOLM_PCAP_DIR = os.environ.get("MALCOLM_PCAP_DIR", "/opt/Malcolm/pcap")

# Resolve project pcap directory dynamically based on script location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
PROJECT_PCAP_DIR = os.path.join(PROJECT_DIR, "pcaps")

def log(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

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

def ingest_to_malcolm(file_name):
    """Copies the PCAP to Malcolm's monitored directory for processing."""
    src = os.path.join(PROJECT_PCAP_DIR, file_name)
    dst = os.path.join(MALCOLM_PCAP_DIR, file_name)
    
    if not validate_pcap(src):
        return False
    
    try:
        log(f"Starting ingestion for {file_name}...")
        shutil.copy2(src, dst)
        log(f"Successfully moved {file_name} to Malcolm ingestion engine.")
        log(f"Processing started. Check dashboards at https://localhost/dashboards")
        return True
    except Exception as e:
        log(f"Failed to ingest {file_name}: {str(e)}", "ERROR")
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
        files = [f for f in os.listdir(PROJECT_PCAP_DIR) if f.endswith(('.pcap', '.pcapng'))]
        for f in files:
            ingest_to_malcolm(f)
    elif args.file:
        ingest_to_malcolm(args.file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
