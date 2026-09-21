# MITRE ATT&CK ICS Threat Hunting Guide

**Focus area:** Industrial Control Systems (ICS) / Modbus TCP
**Framework:** MITRE ATT&CK for ICS **v19.2** (97 techniques), the version pinned
in [ot-detection-engineering](https://github.com/LiamCarPer/ot-detection-engineering)
at `metadata/attack_ics_catalog.json`.

> **On technique IDs.** The ICS techniques were restructured after v13, so older
> mappings no longer resolve. Every ID and name below was checked against the
> pinned catalog, and `automation/tests/test_ingest.py` validates the techniques
> the pipeline asserts against the same file. Two examples of what changed:
> alarm suppression is now **T0878** (not T0804), and an unauthorized control
> command is **T1692.001 Command Message** (not T0855).

> **On query syntax.** Field names differ between capture tools and a SIEM. The
> `tshark` names below are the ones this pipeline uses and are verified against
> the committed captures; the Arkime form is the one used in the committed
> screenshot. An OpenSearch query would need your deployment's field mapping for
> the Zeek or Arkime Modbus fields — check the schema rather than assuming.

---

## Threat Hunt 1: Enumeration of control assets (T0846, T0888)

**Objective:** Find a host reading from several control assets in a short window
— the step before a write.

### Query

```bash
# One source touching three or more control assets with read function codes
tshark -r pcaps/modbus_recon_fanout.pcap \
  -Y "mbtcp && tcp.dstport == 502 && modbus.func_code in {1,2,3,4}" \
  -T fields -e ip.src -e ip.dst -e modbus.func_code
```

Arkime, over the same traffic (from the committed screenshot):

```
tags == "modbus" && ip == 172.24.0.10
```

### Analysis steps

1. Count distinct destinations per source over the window. One master polling one
   PLC is normal; one source fanning out is not.
2. Check each destination against the asset inventory for zone and criticality.
3. Ask whether the source has any operational reason to read those assets.

**Detection status:** *no rule covers this.* The DPI profiler in this repository
asserts T0888 on the committed fan-out capture, but the Suricata ruleset has no
read-enumeration rule, so nothing alerts. This is the first rule worth adding,
and it needs a window, which means stateful detection.

---

## Threat Hunt 2: Unauthorized control write (T0836, T1692.001)

**Objective:** Detect a write to a control asset from a host that is not an
authorized control writer.

### Query

```bash
# Modbus write function codes addressed to the server port
tshark -r pcaps/setpoint_write.pcap \
  -Y "mbtcp && tcp.dstport == 502 && modbus.func_code in {5,6,15,16}" \
  -T fields -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num
```

### Analysis steps

1. Identify the register addresses being written. The pipeline treats `>= 1000` as
   setpoint-class in this lab; in a real site, take the threshold from the
   register map, not from this file.
2. Check the source against the write allowlist. The pipeline answers this
   directly in the report: **Source Authorized to Write**.
3. Compare the value against the operational baseline and the current change
   window before calling it malicious — an authorized engineer making a setpoint
   change looks identical on the wire.

**Detection status:** covered. SID 9000001 fires on `setpoint_write.pcap`; see
`detection-engineering/evidence/setpoint_write.json`.

---

## Threat Hunt 3: Alarm and reporting manipulation (T0878, T0838, T1692.002)

**Objective:** Find writes that disable or falsify alarms rather than change the
process, which is how an operator is prevented from noticing Hunt 2.

### Query

```bash
# Writes to a plausible alarm-configuration register range
tshark -r capture.pcap \
  -Y "mbtcp && tcp.dstport == 502 && modbus.func_code in {5,6,15,16} && modbus.reference_num >= 4000" \
  -T fields -e ip.src -e ip.dst -e modbus.reference_num
```

### Analysis steps

1. Confirm the register range against the alarm configuration map — the range
   above is a placeholder, not a finding.
2. Correlate in time with process alarms and with Hunt 2: suppression usually
   precedes or follows a control write.
3. Treat alarm silence as an event in its own right, not as an absence of events.

**Detection status:** *not covered.* No rule addresses alarm registers.

---

## Threat Hunt 4: Program download (T0843)

**Objective:** Detect a controller logic change, which outlives any register
write and survives a restart.

### Query

```bash
# S7comm program download function, for the S7 captures the ruleset covers
tshark -r capture.pcap -Y "s7comm" -T fields -e ip.src -e ip.dst -e s7comm.function
```

### Analysis steps

1. Any program download outside a maintenance window is an engineering change
   that must be traced to a change record.
2. Compare the logic checksum before and after if the PLC supports it.

**Detection status:** covered in `ot-detection-engineering` (S7comm rules); not
exercised by the captures in this repository, which are Modbus only.

---

## ATT&CK for ICS mapping (validated against v19.2)

| ID | Technique | Tactic | In this repository |
| :--- | :--- | :--- | :--- |
| T0846 | Remote System Discovery | Discovery | Hunting query only |
| T0888 | Remote System Information Discovery | Discovery | Asserted by the DPI profiler |
| T0836 | Modify Parameter | Impair Process Control | Asserted on writes |
| T1692.001 | Command Message | Impair Process Control | Asserted on setpoint-class writes |
| T0878 | Alarm Suppression | Inhibit Response Function | Hunting query only |
| T0838 | Modify Alarm Settings | Inhibit Response Function | Hunting query only |
| T0843 | Program Download | Lateral Movement / Persistence | Covered in ot-detection-engineering |

Related techniques worth having in the plan: T1691.001 Block Command Message,
T1695 Block Communications, T0814 Denial of Service, T0813 Denial of Control,
T0866 Exploitation of Remote Services, T0886 Remote Services.
