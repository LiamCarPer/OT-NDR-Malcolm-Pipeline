# Incident Report: Unauthorized Modbus Setpoint Write
**Report ID:** IR-20260921-175827-MODBUS  
**Classification:** Internal / OT-Confidential  
**Status:** Open / Investigating  
**Incident Lead:** Liam Carvajal (Automated)

---

## 1. Executive Summary
On September 21, 2026, the OT monitoring system flagged a CRITICAL severity alert. Unauthorized Setpoint Manipulation was detected against Intake PLC (PLC-01) (172.21.0.10) in the Purdue Level 1 (Control Zone). The event was automatically triaged by the OT-NDR Orchestration Pipeline.

## 2. Incident Timeline (UTC)
| Timestamp | Event | Action Taken |
| :--- | :--- | :--- |
| 17:58:27 | Alert Triggered: Unauthorized Modbus Setpoint Write | Automatic PCAP Ingestion & DPI Analysis. |
| 17:58:27 | Forensic Hash Generated: b96455802c695f0f3d0c7adf2cdfed7ba2238ff778957537f0d3b6266ad85bff | Integrity verified. |
| 17:58:27 | Asset Context Enriched: Intake PLC (PLC-01) identified. | Context added to report. |

## 3. Analysis and Forensic Evidence
### Network Forensics (DPI Analysis)
- **Source IP:** 172.24.0.10 (Engineering HMI (HMI-01) - Purdue Level 2 (Supervisory Zone))
- **Source Authorized to Write:** No (asset is not an allowlisted control writer)
- **Destination IP:** 172.21.0.10 (Intake PLC (PLC-01) - Purdue Level 1 (Control Zone))
- **Protocol:** Modbus TCP (Port 502)
- **Modbus Requests Analysed:** 7
- **Function Codes Detected:** 3, 6
- **Control Operations (Writes):** 1 detected.
- **Setpoint-Class Writes (register >= 1000):** 1 detected.

### MITRE ATT&CK ICS Mapping
The rows below are derived from the operations actually observed. A capture with no control writes cannot assert a write technique.

| ID | Technique | Description |
| :--- | :--- | :--- |
| T0836 | Modify Parameter | Modbus write commands observed. |
| T1692.001 | Command Message | Write to a setpoint-class register (>= 1000). |

## 4. Asset Context (Inventory Lookup)
- **Asset Name:** Intake PLC (PLC-01)
- **Asset Type:** Programmable Logic Controller
- **Criticality:** High
- **Owner:** OT Operations Team

## 5. Next Steps
- [ ] Confirm whether 172.24.0.10 is expected to issue control writes in this window.
- [ ] Inspect Malcolm dashboard for associated traffic flows.
- [ ] Confirm physical state of Intake PLC (PLC-01).
- [ ] Triage 172.24.0.10 for compromise before restoring normal trust.
