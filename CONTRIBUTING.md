# Contributing to OT-NDR-Malcolm-Pipeline

Thank you for your interest in improving this project. To maintain high engineering standards, please follow these guidelines.

## Development Workflow

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/LiamCarPer/OT-NDR-Malcolm-Pipeline.git
    cd OT-NDR-Malcolm-Pipeline
    ```

2.  **Environment Setup**:
    It is recommended to use a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r automation/requirements.txt
    ```

3.  **Local Testing**:
    Before submitting any changes, ensure all tests pass:
    ```bash
    pytest automation/tests/
    ```
    Some tests read the committed captures with the real `tshark` binary and are
    skipped if it is not installed. `sudo apt-get install tshark` to run them.

4.  **Code Quality**:
    Lint with the committed configuration before committing:
    ```bash
    flake8 automation/ detection-engineering/ pcaps/ assets/
    ```

## Adding New Features

- **DPI Logic**: If adding support for new industrial protocols (e.g., S7comm,
  EtherNet/IP), extend `analyze_pcap_dpi` and add a capture test in
  `automation/tests/` that reads a committed capture rather than a mock.
- **Orchestration**: For new SOAR triggers, update `generate_incident_report`
  and the placeholders in `Incident_Report_Template.md` together, and add a test
  that proves the new field is derived from the analysis.
- **Forensic logging**: `automation/ingest_audit.log` is append-only and machine
  readable — one JSON object per line, never free text. Human-readable progress
  goes to stdout only.
- **Captures**: `pcaps/` is evidence. If you add or change a capture, update
  `pcaps/README.md`, re-run the pipeline so the audit log matches, re-run
  `detection-engineering/suricata_check.py` so the alert evidence is not stale,
  and re-run `automation/detection_quality.py`. `automation/tests/test_ingest.py`
  fails if the evidence and the capture hashes disagree, or if the quality table
  in `README.md` drifts from the generated metric.
- **Change windows**: `automation/change_windows.json` is the approved change
  calendar. Severity is a function of the operation, the asset criticality and
  whether a window covers the event time read from the capture. A window explains
  the timing of an operation, not the identity of the host performing it.
- **Triage**: after triaging a report, record the outcome. The metric is only
  worth having if the decisions behind it are recorded:
  ```bash
  python3 automation/detection_quality.py --record \
      --capture setpoint_write.pcap --disposition true_positive \
      --note "confirmed unauthorised write; change window did not cover it"
  ```
  Valid dispositions: `true_positive`, `expected_change`, `benign`,
  `false_positive`, `duplicate`, `inconclusive`. The unit of triage is the
  capture, so every detection that fired on it inherits the outcome; re-triaging
  appends a newer record and the latest wins.
- **Detection content** does not live here. Rules belong in
  [ot-detection-engineering](https://github.com/LiamCarPer/ot-detection-engineering).

## Bug Reports and Feature Requests

Please use the GitHub Issue tracker to report bugs or suggest enhancements. Provide a clear description and, if possible, a sample PCAP to reproduce any issues.

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.
