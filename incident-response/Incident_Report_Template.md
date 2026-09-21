# Incident Report: {{ ALERT_MESSAGE }}
**Report ID:** IR-{{ TIMESTAMP_ID }}-MODBUS  
**Classification:** Internal / OT-Confidential  
**Status:** Open / Investigating  
**Incident Lead:** {{ INCIDENT_LEAD }}  
**Report generated:** {{ REPORT_DATE }} {{ REPORT_TIME }} UTC

---

## 1. Executive Summary
On {{ EVENT_DATE }}, the OT monitoring system flagged a {{ SEVERITY }} severity alert. {{ ATTACK_TYPE }} was detected against {{ TARGET_ASSET }} ({{ TARGET_IP }}) in the {{ TARGET_ZONE }}. The event was automatically triaged by the OT-NDR Orchestration Pipeline.

- **Severity basis:** {{ SEVERITY_BASIS }}
- **Change window:** {{ CHANGE_WINDOW }}
- **Detections:** {{ DETECTIONS }}

## 2. Trigger
{{ TRIGGER_SECTION }}

## 3. Incident Timeline (UTC)
| Timestamp | Event | Action Taken |
| :--- | :--- | :--- |
| {{ EVENT_WINDOW }} | Activity observed in `{{ CAPTURE_NAME }}` | Deep packet inspection and asset-context enrichment. |
| {{ REPORT_TIMESTAMP }} | Forensic hash generated: {{ SHA256 }} | Integrity verified. |
| {{ REPORT_TIMESTAMP }} | Report generated. | Detections recorded in `automation/ingest_audit.log`. |

## 4. Analysis and Forensic Evidence
### Network Forensics (DPI Analysis)
- **Source IP:** {{ SOURCE_IP }} ({{ SOURCE_ASSET }} - {{ SOURCE_ZONE }})
- **Source Authorized to Write:** {{ SOURCE_AUTHORIZED }}
- **Destination IP:** {{ TARGET_IP }} ({{ TARGET_ASSET }} - {{ TARGET_ZONE }})
- **Protocol:** Modbus TCP (Port 502)
- **Modbus Requests Analysed:** {{ REQUEST_COUNT }}
- **Function Codes Detected:** {{ FUNC_CODES }}
- **Control Operations (Writes):** {{ WRITE_COUNT }} detected.
- **Setpoint-Class Writes (register >= 1000):** {{ CRITICAL_WRITE_COUNT }} detected.

### MITRE ATT&CK ICS Mapping
The rows below are derived from the operations actually observed. A capture with no control writes cannot assert a write technique.

| ID | Technique | Description |
| :--- | :--- | :--- |
{{ MITRE_ROWS }}

## 5. Asset Context (Inventory Lookup)
- **Asset Name:** {{ TARGET_ASSET }}
- **Asset Type:** {{ TARGET_TYPE }}
- **Criticality:** {{ TARGET_CRITICALITY }}
- **Owner:** {{ TARGET_OWNER }}

## 6. Next Steps
- [ ] Confirm whether {{ SOURCE_IP }} is expected to issue control writes in this window.
- [ ] Inspect Malcolm dashboard for associated traffic flows.
- [ ] Confirm physical state of {{ TARGET_ASSET }}.
- [ ] Triage {{ SOURCE_IP }} for compromise before restoring normal trust.
- [ ] Record the outcome with `python3 automation/detection_quality.py --record`.
