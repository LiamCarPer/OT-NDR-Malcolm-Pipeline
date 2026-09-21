# Incident Report: Unauthorized Modbus Setpoint Write
**Report ID:** IR-20260921-222035-MODBUS  
**Classification:** Internal / OT-Confidential  
**Status:** Open / Investigating  
**Incident Lead:** Liam Carvajal (Automated)  
**Report generated:** September 21, 2026 22:20:35 UTC

---

## 1. Executive Summary
On May 01, 2026, the OT monitoring system flagged a CRITICAL severity alert. Unauthorized Setpoint Manipulation was detected against Intake PLC (PLC-01) (172.21.0.10) in the Purdue Level 1 (Control Zone). The event was automatically triaged by the OT-NDR Orchestration Pipeline.

- **Severity basis:** Setpoint-class write against a high-criticality asset, and no approved change window covers the event.
- **Change window:** No approved change window covers the event (`automation/change_windows.json`).
- **Detections:** `sid:9000001`, `dpi:setpoint_write`

## 2. Trigger
This report was triggered by 1 IDS alert. Evidence: `detection-engineering/evidence/setpoint_write.json`.

| SID | Signature | Event time |
| :--- | :--- | :--- |
| 9000001 | OT Modbus Write Single Register From Unauthorized Control Writer | 2026-05-01T10:32:00Z |

## 3. Incident Timeline (UTC)
| Timestamp | Event | Action Taken |
| :--- | :--- | :--- |
| 2026-05-01 10:31:00 – 10:32:00 | Activity observed in `setpoint_write.pcap` | Deep packet inspection and asset-context enrichment. |
| 2026-09-21 22:20:35 | Forensic hash generated: b96455802c695f0f3d0c7adf2cdfed7ba2238ff778957537f0d3b6266ad85bff | Integrity verified. |
| 2026-09-21 22:20:35 | Report generated. | Detections recorded in `automation/ingest_audit.log`. |

## 4. Analysis and Forensic Evidence
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

## 5. Asset Context (Inventory Lookup)
- **Asset Name:** Intake PLC (PLC-01)
- **Asset Type:** Programmable Logic Controller
- **Criticality:** High
- **Owner:** OT Operations Team

## 6. Next Steps
- [ ] Confirm whether 172.24.0.10 is expected to issue control writes in this window.
- [ ] Inspect Malcolm dashboard for associated traffic flows.
- [ ] Confirm physical state of Intake PLC (PLC-01).
- [ ] Triage 172.24.0.10 for compromise before restoring normal trust.
- [ ] Record the outcome with `python3 automation/detection_quality.py --record`.
