# Incident Report: Modbus Baseline Drift
**Report ID:** IR-20260921-175510-MODBUS  
**Classification:** Internal / OT-Confidential  
**Status:** Open / Investigating  
**Incident Lead:** Liam Carvajal (Automated)

---

## 1. Executive Summary
On September 21, 2026, the OT monitoring system flagged a MEDIUM severity alert. Reconnaissance / Baseline Drift was detected against Intake PLC (PLC-01) (172.21.0.10) in the Purdue Level 1 (Control Zone). The event was automatically triaged by the OT-NDR Orchestration Pipeline.

## 2. Incident Timeline (UTC)
| Timestamp | Event | Action Taken |
| :--- | :--- | :--- |
| 17:55:10 | Alert Triggered: Modbus Baseline Drift | Automatic PCAP Ingestion & DPI Analysis. |
| 17:55:10 | Forensic Hash Generated: 63757dc7299c454544bc31c86c177a0aae547d32f94d1ffffd38b3d28b0b2da3 | Integrity verified. |
| 17:55:10 | Asset Context Enriched: Intake PLC (PLC-01) identified. | Context added to report. |

## 3. Analysis and Forensic Evidence
### Network Forensics (DPI Analysis)
- **Source IP:** 172.24.0.10 (Engineering HMI (HMI-01) - Purdue Level 2 (Supervisory Zone))
- **Source Authorized to Write:** No (asset is not an allowlisted control writer)
- **Destination IP:** 172.21.0.10 (Intake PLC (PLC-01) - Purdue Level 1 (Control Zone))
- **Protocol:** Modbus TCP (Port 502)
- **Modbus Requests Analysed:** 3
- **Function Codes Detected:** 3
- **Control Operations (Writes):** 0 detected.
- **Setpoint-Class Writes (register >= 1000):** 0 detected.

### MITRE ATT&CK ICS Mapping
The rows below are derived from the operations actually observed. A capture with no control writes cannot assert a write technique.

| ID | Technique | Description |
| :--- | :--- | :--- |
| T0888 | Remote System Information Discovery | Read-only requests fanning out across several control assets. |

## 4. Asset Context (Inventory Lookup)
- **Asset Name:** Intake PLC (PLC-01)
- **Asset Type:** Programmable Logic Controller
- **Criticality:** High
- **Owner:** OT Operations Team

## 5. Next Steps
- [ ] Confirm whether 172.24.0.10 is expected to issue control writes in this window.
- [ ] Inspect Malcolm dashboard for associated traffic flows.
- [ ] Confirm physical state of Intake PLC (PLC-01).
- [ ] Rotate credentials if lateral movement is confirmed.
