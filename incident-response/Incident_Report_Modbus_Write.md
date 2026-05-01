# Incident Report: Unauthorized Modbus Setpoint Manipulation
**Report ID:** IR-20260430-MODBUS-01  
**Classification:** Internal / OT-Confidential  
**Status:** Closed / Resolved  
**Incident Lead:** Liam Carvajal

---

## 1. Executive Summary
On May 1, 2026, the OT monitoring system (CISA Malcolm) flagged a high-severity alert indicating unauthorized Modbus TCP write commands directed at a Programmable Logic Controller (PLC) residing in the Purdue Level 1 zone. The attacker, originating from a compromised engineering workstation in Level 3, attempted to modify a critical process setpoint. The incident was detected, analyzed, and contained within 45 minutes, preventing physical process disruption.

## 2. Incident Timeline (UTC)
| Timestamp | Event | Action Taken |
| :--- | :--- | :--- |
| 11:38:00 | Baseline: Normal HMI polling observed (1220 packets). | System functioning normally. |
| 12:25:10 | Discovery: Internal scan for Modbus (Port 502) targets. | Arkime SPI Graph identifies scanning. |
| 12:26:05 | Exploitation: Modbus FC 6 (Write) sent to PLC-01 (172.21.0.10). | Suricata SID: 1000001 triggered. |
| 14:23:45 | Detection: Security Analyst notified via OpenSearch Dashboard. | Triage initiated. |
| 14:40:00 | Containment: Source IP isolated at the Level 3.5 Firewall. | Traffic blocked. |
| 14:55:00 | Recovery: Setpoint verified and restored by OT Operations. | Incident closed. |

## 3. Analysis and Forensic Evidence
### Network Forensics (Arkime/Malcolm)
Analysis of the `modbus_attack_lateral.pcap` reveals a sequence of Modbus packets originating from the IT Zone targeting 172.21.0.10 (Control Zone). 
- Packet Evidence: Modbus Write Single Register command detected.
- Target IP: 172.21.0.10 (Intake PLC).

### MITRE ATT&CK ICS Mapping
| ID | Technique | Description |
| :--- | :--- | :--- |
| T0836 | Modify Parameter | Altering the pressure setpoint to exceed safety thresholds. |
| T0890 | Lateral Movement | Moving from Level 3 IT/OT boundary to Level 1 Control Zone. |
| T0831 | Manipulation of Control | Sending unauthorized Modbus commands to change process logic. |

## 4. Containment, Eradication, and Recovery
- Short-term: Isolated the compromised Engineering Workstation.
- Eradication: Performed malware sweep and credential rotation on the workstation.
- Recovery: Cross-referenced PLC register values with physical baseline and restored manual control.

## 5. Post-Incident Analysis
Root Cause: Improper micro-segmentation between the Engineering Workstation and the Control Zone, allowing direct Modbus communication across Purdue levels.

Lessons Learned:
1. Implementation of firewall rules should restrict Modbus traffic to specific, authenticated sessions.
2. Deployment of persistent honey-registers would provide earlier warning of reconnaissance activity.
