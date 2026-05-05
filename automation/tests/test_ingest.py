import pytest
import os
import hashlib
import sys
import json
from unittest.mock import MagicMock, patch

# Add parent directory to path to import malcolm_ingest
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import malcolm_ingest

def test_calculate_sha256(tmp_path):
    """Test that SHA-256 calculation is accurate."""
    content = b"forensic test pcap content"
    test_file = tmp_path / "forensic_test.pcap"
    test_file.write_bytes(content)
    
    expected_hash = hashlib.sha256(content).hexdigest()
    actual_hash = malcolm_ingest.calculate_sha256(str(test_file))
    
    assert actual_hash == expected_hash

@patch('malcolm_ingest.subprocess.run')
def test_analyze_pcap_dpi_basic(mock_run):
    """Test DPI analysis with mock tshark output."""
    # Mock tshark output: src_ip, dst_ip, func_code, reference_num
    mock_run.return_value = MagicMock(
        stdout="192.168.1.5\t192.168.1.10\t16\t1050\n192.168.1.5\t192.168.1.10\t3\t50",
        returncode=0
    )
    
    stats = malcolm_ingest.analyze_pcap_dpi("mock.pcap")
    assert stats["total_packets"] == 2
    assert stats["writes"] == 1
    assert stats["critical_writes"] == 1
    assert "T0836" in stats["mitre_tags"]
    assert "T0855" in stats["mitre_tags"]

@patch('malcolm_ingest.subprocess.run')
def test_sanitize_pcap_success(mock_run):
    """Test that sanitization triggers tcprewrite."""
    mock_run.return_value = MagicMock(returncode=0)
    result = malcolm_ingest.sanitize_pcap("in.pcap", "out.pcap")
    assert result == True
    mock_run.assert_called_once()

@patch('malcolm_ingest.load_inventory')
def test_generate_incident_report_content(mock_load, tmp_path):
    """Test incident report content generation with context."""
    mock_load.return_value = {
        "192.168.1.10": {
            "name": "Production PLC",
            "zone": "Cell 1",
            "type": "PLC",
            "criticality": "CRITICAL",
            "owner": "OT-Admin"
        }
    }
    
    stats = {
        "src_ips": ["192.168.1.5"],
        "dst_ips": ["192.168.1.10"],
        "func_codes": ["16"],
        "reads": 0,
        "writes": 1,
        "critical_writes": 1,
        "total_packets": 1
    }
    
    with patch('malcolm_ingest.REPORT_TEMPLATE', str(tmp_path / "template.md")):
        with patch('malcolm_ingest.REPORT_OUTPUT_DIR', str(tmp_path)):
            with open(tmp_path / "template.md", 'w') as f:
                f.write("Alert: {{ ALERT_MESSAGE }} | Target: {{ TARGET_ASSET }} | Criticality: {{ TARGET_CRITICALITY }}")
                
            report_path = malcolm_ingest.generate_incident_report(stats, "test.pcap", "mockhash")
            
            assert report_path is not None
            with open(report_path, 'r') as f:
                content = f.read()
                assert "Unauthorized Modbus Write" in content
                assert "Production PLC" in content
                assert "CRITICAL" in content
