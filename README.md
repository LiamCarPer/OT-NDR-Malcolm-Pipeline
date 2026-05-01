# OT Network Detection & Response (NDR) Pipeline using CISA Malcolm

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Framework: CISA Malcolm](https://img.shields.io/badge/Framework-CISA%20Malcolm-blue)](https://malcolm.fyi/)

## Objective
To emulate the Continuous Threat Detection (CTD) and passive asset visibility of commercial platforms like Nozomi Networks and Claroty using open-source tools. This project demonstrates a production-grade pipeline for industrial network security, specifically focused on Deep Packet Inspection (DPI) of the Modbus TCP protocol within a Purdue-model environment.

## Architecture
The pipeline ingests raw network traffic (PCAPs) from a simulated Industrial Control System (ICS) environment.

1.  **Traffic Capture:** Real-time capture of Modbus TCP traffic between HMIs and PLCs.
2.  **Ingestion:** Automatic processing via **CISA Malcolm**.
3.  **Analysis:** Protocol decoding and SPI (Stateful Packet Inspection) via **Arkime**.
4.  **Detection:** Alert generation via **Suricata** IDS with custom industrial rules.
5.  **Visibility:** Asset discovery and threat hunting via **OpenSearch** dashboards.

---

## Key Capabilities Demonstrated
- **Deep Packet Inspection (DPI)**: Analysis of Modbus TCP function codes and register values to detect logic manipulation.
- **Passive Asset Discovery**: Automated identification of PLCs, HMIs, and workstations without active scanning, preserving operational uptime.
- **Detection Engineering**: Development of custom Suricata IDS rules to identify unauthorized ICS commands.
- **Incident Response**: Forensic investigations aligned with NIST SP 800-61 and mapped to the MITRE ATT&CK for ICS matrix.

## Repository Structure
```bash
OT-NDR-Malcolm-Pipeline/
├── README.md                           # Master project summary
├── pcaps/                              # Raw network traffic data (Baseline vs. Attack)
├── detection-engineering/              # Custom Suricata rules for Modbus
├── dashboards-and-visibility/          # Proof of SIEM/NDR visualization
└── incident-response/                  # NIST-aligned forensic reporting & threat hunting
```

---

## Visibility and Analytics
### Passive Asset Discovery
Malcolm automatically identifies assets by analyzing traffic patterns. Below is the dashboard showing the discovery of PLC and HMI nodes.
![Passive Asset Discovery](dashboards-and-visibility/passive_asset_discovery.png)

### Lateral Movement Analysis
Using Arkime SPI Graphs, network connections are visualized to identify anomalous traffic flows across Purdue levels.
![Arkime Lateral Movement](dashboards-and-visibility/arkime_lateral_movement.png)

## Incident Response and Threat Hunting
The project includes a comprehensive Incident Report documenting a simulated setpoint manipulation attack. Findings are mapped to the MITRE ATT&CK ICS Matrix to provide a standardized view of the threat actor's tactics.

---

## 🛠️ Tech Stack
-   **NDR Framework:** CISA Malcolm
-   **IDS/IPS:** Suricata
-   **Forensics:** Arkime (formerly Moloch)
-   **SIEM/Visualization:** OpenSearch / Dashboards
-   **Protocols:** Modbus TCP (ICS/SCADA)
