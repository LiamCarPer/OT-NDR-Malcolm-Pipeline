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

4.  **Code Quality**:
    We follow PEP 8 standards. Please run a linter before committing:
    ```bash
    flake8 automation/
    ```

## Adding New Features

- **DPI Logic**: If adding support for new industrial protocols (e.g., S7Comm, EtherNet/IP), ensure you update `analyze_pcap_dpi` and add corresponding test cases in `tests/`.
- **Orchestration**: For new SOAR triggers, update `generate_incident_report` and ensure the `REPORT_TEMPLATE.md` is updated with necessary placeholders.

## Bug Reports and Feature Requests

Please use the GitHub Issue tracker to report bugs or suggest enhancements. Provide a clear description and, if possible, a sample PCAP to reproduce any issues.

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.
