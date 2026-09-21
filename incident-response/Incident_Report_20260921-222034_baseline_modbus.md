# Incident Report: Modbus Baseline Drift
**Report ID:** IR-20260921-222034-MODBUS  
**Classification:** Internal / OT-Confidential  
**Status:** Open / Investigating  
**Incident Lead:** Liam Carvajal (Automated)  
**Report generated:** September 21, 2026 22:20:34 UTC

---

## 1. Executive Summary
On April 30, 2026, the OT monitoring system flagged a MEDIUM severity alert. Baseline Drift was detected against Intake PLC (PLC-01) (172.21.0.10) in the Purdue Level 1 (Control Zone). The event was automatically triaged by the OT-NDR Orchestration Pipeline.

- **Severity basis:** Read-only traffic with no control operation against a high-criticality asset, and no approved change window covers the event.
- **Change window:** No approved change window covers the event (`automation/change_windows.json`).
- **Detections:** `dpi:drift`

## 2. Trigger
No IDS alert triggered this report. It was forced with `--trigger-alert`, so it reflects the DPI profile below rather than a detection.

## 3. Incident Timeline (UTC)
| Timestamp | Event | Action Taken |
| :--- | :--- | :--- |
| 2026-04-30 18:32:42 – 18:43:43 | Activity observed in `baseline_modbus.pcap` | Deep packet inspection and asset-context enrichment. |
| 2026-09-21 22:20:34 | Forensic hash generated: 41b1f9e383fabde7ace30faffa2133eb1be50c135f4bfb4e9cc98f387d8e788a | Integrity verified. |
| 2026-09-21 22:20:34 | Report generated. | Detections recorded in `automation/ingest_audit.log`. |

## 4. Analysis and Forensic Evidence
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

## 5. Asset Context (Inventory Lookup)
- **Asset Name:** Intake PLC (PLC-01)
- **Asset Type:** Programmable Logic Controller
- **Criticality:** High
- **Owner:** OT Operations Team

## 6. Next Steps
- [ ] Confirm whether 172.21.0.1 is expected to issue control writes in this window.
- [ ] Inspect Malcolm dashboard for associated traffic flows.
- [ ] Confirm physical state of Intake PLC (PLC-01).
- [ ] Triage 172.21.0.1 for compromise before restoring normal trust.
- [ ] Record the outcome with `python3 automation/detection_quality.py --record`.
