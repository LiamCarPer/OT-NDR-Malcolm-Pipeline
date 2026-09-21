# Incident Report: Modbus Baseline Drift
**Report ID:** IR-20260921-172918-MODBUS  
**Classification:** Internal / OT-Confidential  
**Status:** Open / Investigating  
**Incident Lead:** Liam Carvajal (Automated)

---

## 1. Executive Summary
On September 21, 2026, the OT monitoring system flagged a MEDIUM severity alert. Reconnaissance / Baseline Drift was detected against Intake PLC (PLC-01) (172.21.0.10) in the Purdue Level 1 (Control Zone). The event was automatically triaged by the OT-NDR Orchestration Pipeline.

## 2. Incident Timeline (UTC)
| Timestamp | Event | Action Taken |
| :--- | :--- | :--- |
| 17:29:18 | Alert Triggered: Modbus Baseline Drift | Automatic PCAP Ingestion & DPI Analysis. |
| 17:29:18 | Forensic Hash Generated: 41b1f9e383fabde7ace30faffa2133eb1be50c135f4bfb4e9cc98f387d8e788a | Integrity verified. |
| 17:29:18 | Asset Context Enriched: Intake PLC (PLC-01) identified. | Context added to report. |

## 3. Analysis and Forensic Evidence
### Network Forensics (DPI Analysis)
- **Source IP:** 172.21.0.1 (Unknown Asset - Unknown)
- **Source Authorized to Write:** Unknown (source is not in the asset inventory)
- **Destination IP:** 172.21.0.10 (Intake PLC (PLC-01) - Purdue Level 1 (Control Zone))
- **Protocol:** Modbus TCP (Port 502)
- **Modbus Requests Analysed:** 610
- **Function Codes Detected:** 3
- **Control Operations (Writes):** 0 detected.
- **Setpoint-Class Writes (register >= 1000):** 0 detected.

### MITRE ATT&CK ICS Mapping
The rows below are derived from the operations actually observed. A capture with no control writes cannot assert a write technique.

| ID | Technique | Description |
| :--- | :--- | :--- |
| — | — | No ATT&CK for ICS technique is asserted for this traffic. |

## 4. Asset Context (Inventory Lookup)
- **Asset Name:** Intake PLC (PLC-01)
- **Asset Type:** Programmable Logic Controller
- **Criticality:** High
- **Owner:** OT Operations Team

## 5. Next Steps
- [ ] Confirm whether 172.21.0.1 is expected to issue control writes in this window.
- [ ] Inspect Malcolm dashboard for associated traffic flows.
- [ ] Confirm physical state of Intake PLC (PLC-01).
- [ ] Rotate credentials if lateral movement is confirmed.
