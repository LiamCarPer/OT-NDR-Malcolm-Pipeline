# Incident Report: Modbus Read Enumeration
**Report ID:** IR-20260921-222034-MODBUS  
**Classification:** Internal / OT-Confidential  
**Status:** Open / Investigating  
**Incident Lead:** Liam Carvajal (Automated)  
**Report generated:** September 21, 2026 22:20:34 UTC

---

## 1. Executive Summary
On May 01, 2026, the OT monitoring system flagged a MEDIUM severity alert. Reconnaissance was detected against Intake PLC (PLC-01) (172.21.0.10) in the Purdue Level 1 (Control Zone). The event was automatically triaged by the OT-NDR Orchestration Pipeline.

- **Severity basis:** Read-only fan-out across control assets against a high-criticality asset, and no approved change window covers the event.
- **Change window:** No approved change window covers the event (`automation/change_windows.json`).
- **Detections:** `dpi:read_fanout`

## 2. Trigger
No IDS alert triggered this report. It was forced with `--trigger-alert`, so it reflects the DPI profile below rather than a detection.

## 3. Incident Timeline (UTC)
| Timestamp | Event | Action Taken |
| :--- | :--- | :--- |
| 2026-05-01 10:27:07 – 10:27:21 | Activity observed in `modbus_recon_fanout.pcap` | Deep packet inspection and asset-context enrichment. |
| 2026-09-21 22:20:34 | Forensic hash generated: 63757dc7299c454544bc31c86c177a0aae547d32f94d1ffffd38b3d28b0b2da3 | Integrity verified. |
| 2026-09-21 22:20:34 | Report generated. | Detections recorded in `automation/ingest_audit.log`. |

## 4. Analysis and Forensic Evidence
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
