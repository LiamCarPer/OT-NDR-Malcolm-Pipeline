# Incident Report: {{ ALERT_MESSAGE }}
**Report ID:** IR-{{ TIMESTAMP_ID }}-MODBUS  
**Classification:** Internal / OT-Confidential  
**Status:** Open / Investigating  
**Incident Lead:** {{ INCIDENT_LEAD }}

---

## 1. Executive Summary
On {{ DATE }}, the OT monitoring system flagged a {{ SEVERITY }} severity alert. A {{ ATTACK_TYPE }} was detected targeting {{ TARGET_ASSET }} ({{ TARGET_IP }}) in the {{ TARGET_ZONE }}. The event was automatically triaged by the OT-NDR Orchestration Pipeline.

## 2. Incident Timeline (UTC)
| Timestamp | Event | Action Taken |
| :--- | :--- | :--- |
| {{ EVENT_TIME }} | Alert Triggered: {{ ALERT_MESSAGE }} | Automatic PCAP Ingestion & DPI Analysis. |
| {{ EVENT_TIME }} | Forensic Hash Generated: {{ SHA256 }} | Integrity verified. |
| {{ EVENT_TIME }} | Asset Context Enriched: {{ TARGET_ASSET }} identified. | Context added to report. |

## 3. Analysis and Forensic Evidence
### Network Forensics (DPI Analysis)
- **Source IP:** {{ SOURCE_IP }} ({{ SOURCE_ASSET }} - {{ SOURCE_ZONE }})
- **Destination IP:** {{ TARGET_IP }} ({{ TARGET_ASSET }} - {{ TARGET_ZONE }})
- **Protocol:** Modbus TCP (Port 502)
- **Function Codes Detected:** {{ FUNC_CODES }}
- **Control Operations (Writes):** {{ WRITE_COUNT }} detected.

### MITRE ATT&CK ICS Mapping
| ID | Technique | Description |
| :--- | :--- | :--- |
| T0836 | Modify Parameter | Detected unauthorized Modbus Write commands. |
| T0890 | Lateral Movement | Originating from {{ SOURCE_ZONE }}. |

## 4. Asset Context (Inventory Lookup)
- **Asset Name:** {{ TARGET_ASSET }}
- **Asset Type:** {{ TARGET_TYPE }}
- **Criticality:** {{ TARGET_CRITICALITY }}
- **Owner:** {{ TARGET_OWNER }}

## 5. Next Steps
- [ ] Verify if {{ SOURCE_IP }} is authorized for these operations.
- [ ] Inspect Malcolm dashboard for associated traffic flows.
- [ ] Confirm physical state of {{ TARGET_ASSET }}.
- [ ] Rotate credentials if lateral movement is confirmed.
