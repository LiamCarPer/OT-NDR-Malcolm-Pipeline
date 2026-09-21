# Incident Report: Unauthorized Modbus Setpoint Manipulation

**Report ID:** IR-20260501-MODBUS-01  
**Classification:** Internal / OT-Confidential  
**Status:** Closed — tabletop exercise  
**Incident Lead:** Liam Carvajal

> **Scope note.** This is a **tabletop exercise**, not a response to a live
> incident. The network evidence is real and committed; the response actions in
> section 4 were walked through against NIST SP 800-61, not executed on real
> infrastructure. Nothing below should be read as an operational containment.
>
> Evidence: `pcaps/baseline_modbus.pcap`, `pcaps/modbus_recon_fanout.pcap`,
> `pcaps/setpoint_write.pcap`, with alert evidence in
> `detection-engineering/evidence/` and hashes in `automation/ingest_audit.log`.

---

## 1. Executive Summary
On May 1, 2026, the OT monitoring system flagged a CRITICAL severity alert for an unauthorized Modbus setpoint write against the Intake PLC (PLC-01, `172.21.0.10`) in the Purdue Level 1 control zone. The write originated from the Engineering HMI (`172.24.0.10`), a Purdue Level 2 supervisory asset that is not an allowlisted control writer. It followed a read-only enumeration of three control assets four minutes earlier. The pipeline detected, classified, enriched and reported the event; the response below is the exercise that follows the report.

## 2. Incident Timeline (UTC)

| Timestamp | Event | Evidence |
| :--- | :--- | :--- |
| Apr 30 18:32:42 | Baseline: single master polling PLC-01 with reads only (610 requests over 11 minutes). | `baseline_modbus.pcap`; Suricata: 0 alerts |
| May 1 10:27:07 | Enumeration: `172.24.0.10` issues one read each to PLC-01, SEN-01 and SEN-02 in 14 seconds. | `modbus_recon_fanout.pcap`; DPI asserts T0888 |
| May 1 10:27:21 | Enumeration ends. No alert: the ruleset has no read-enumeration rule. | Coverage gap, section 5 |
| May 1 10:31:00 | Exploitation: `172.24.0.10` polls, then writes value `4200` to holding register `1050` on PLC-01. | `setpoint_write.pcap` |
| May 1 10:32:00 | Detection: Suricata fires **SID 9000001**, "OT Modbus Write Single Register From Unauthorized Control Writer". | `detection-engineering/evidence/setpoint_write.json` |
| May 1 10:32:00 | Automated triage: DPI classification, asset enrichment, CRITICAL report generated. | `incident-response/Incident_Report_*_setpoint_write.md` |
| May 1 (exercise) | Containment: source isolated at the Level 3.5 firewall; setpoint restored from the process baseline. | Planned action, not executed |

## 3. Analysis and Forensic Evidence

### Network forensics

The write capture contains two complete TCP sessions between `172.24.0.10` and
`172.21.0.10:502`: six FC 3 reads (routine polling) and one FC 6 write of `4200`
to holding register `1050`, followed by a read-back. Register `1050` is treated
as setpoint-class by the pipeline (`>= 1000`), which is what escalates the
severity from HIGH to CRITICAL.

- **Source:** `172.24.0.10` — Engineering HMI (HMI-01), Purdue Level 2
- **Source authorized to write:** No — the asset is not an allowlisted control writer
- **Target:** `172.21.0.10` — Intake PLC (PLC-01), Purdue Level 1, criticality High
- **Operation:** Modbus/TCP function code 6, register `1050`, value `4200`

The earlier enumeration capture carries three read requests to three distinct
control assets from the same source. It produced no IDS alert.

### MITRE ATT&CK ICS mapping

| ID | Technique | Basis |
| :--- | :--- | :--- |
| T0888 | Remote System Information Discovery | Three control assets enumerated by one host in 14 seconds |
| T0836 | Modify Parameter | FC 6 write to a control asset |
| T1692.001 | Command Message | Write to a setpoint-class register from a non-allowlisted writer |

### Forensic integrity

Each capture is hashed with SHA-256 on ingestion and the digest is written to the
append-only `automation/ingest_audit.log`. The hash of `setpoint_write.pcap`
(`b96455802c695f0f3d0c7adf2cdfed7ba2238ff778957537f0d3b6266ad85bff`) is recorded
in the alert evidence alongside the Suricata rule's own digest, so the alert can
be tied to the exact bytes that produced it.

## 4. Containment, Eradication and Recovery (exercise)

- **Containment:** isolate the source at the Level 3.5 boundary; confirm no other
  host wrote to PLC-01 in the window.
- **Eradication:** triage the Engineering HMI for compromise; rotate its
  credentials and any credentials it holds.
- **Recovery:** verify register `1050` against the physical process baseline and
  restore the intended setpoint under change control.
- **Follow-up:** confirm whether the write was authorised work outside a change
  window — the most likely benign explanation, and the reason the alert is
  CRITICAL rather than automatically malicious.

## 5. Post-Incident Analysis

**Root cause (exercise):** the Engineering HMI holds network reachability to the
control zone that its role does not require. It polls, so it must reach PLCs, but
it has no need to write.

**What actually went wrong in the tooling, and was fixed:**

1. **The enumeration was invisible.** No rule covers read-only fan-out. The DPI
   profiler asserts T0888 but nothing alerts on it. This is the first rule worth
   adding: N distinct control assets read by one source inside a short window.
2. **The write allowlist lived in the rule, not the asset model.** The ruleset's
   authorized writers (`172.21.0.20`, `172.22.0.10`) and this pipeline's asset
   inventory did not agree. The inventory now carries a `control_writer` flag,
   the report states whether the source is allowed to write, and the allowlist
   has one home.
3. **The earlier captures could not have produced this alert.** They carry Modbus
   payloads on bare SYN packets with no handshake, so no
   `flow:to_server,established` rule could ever match. The claim that a rule
   fired on them was wrong. `setpoint_write.pcap` was built with a complete
   handshake and the rule's firing is now committed as evidence.

**Lessons learned:**

1. An alert that has never been shown to fire is a hypothesis, not a detection.
2. Identity decisions belong in the asset model, where a new HMI is visible,
   rather than in a rule, where it is invisible.
3. Read-only reconnaissance is where the coverage gap is, and it is cheap to
   close.
