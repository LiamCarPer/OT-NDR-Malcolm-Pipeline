# Detection engineering

The Suricata ruleset this pipeline runs is generated and validated in
[ot-detection-engineering](https://github.com/LiamCarPer/ot-detection-engineering).
It is not maintained here, so the two repositories cannot drift apart.

- **Canonical rules:** `rules/native/suricata/*.rules` in that repository.
- **Generated artifact:** `deploy/suricata/ot-detection.rules` (24 rules, SIDs
  `9000001-9000028`) covering Modbus, DNP3, OPC UA and S7comm.
- **Validation in that repository:** `make suricata-check` runs the rules over
  its own captures, and `tools/malcolm_check.py` runs them inside a Malcolm
  installation with the default ruleset enabled; both commit their evidence
  under `deploy/evidence/`.

## Evidence in this repository

The rules are validated there; they are proven to fire on *this* pipeline's
evidence here. `suricata_check.py` runs the generated ruleset over the committed
captures in a container and records the result per capture under `evidence/`.

| Capture | Alerts |
| :--- | :--- |
| `baseline_modbus.pcap` | 0 |
| `modbus_recon_fanout.pcap` | 0 |
| `setpoint_write.pcap` | 1 — SID 9000001, "OT Modbus Write Single Register From Unauthorized Control Writer" |
| `setpoint_write_maintenance.pcap` | 1 — the same rule, on the same class of operation inside an approved change window |

Each evidence file records the SHA-256 of the capture and of the ruleset that
produced the alert, so the claim is tied to exact bytes on both sides.

Two things worth saying plainly:

- **The zero on the benign capture is the useful number.** It is a real
  false-positive measurement over committed traffic, not an authored baseline.
- **The zero on the enumeration capture is a coverage gap, not a success.** The
  ruleset detects control writes; it has no rule for read-only fan-out across
  control assets. The DPI profiler asserts T0888 on it, but nothing alerts.

```bash
python3 detection-engineering/suricata_check.py            # sibling checkout
python3 detection-engineering/suricata_check.py --rules /path/to/ot-detection.rules
```

Modbus and DNP3 application-layer detection is disabled in the stock Suricata
configuration, so the runner enables both parsers explicitly. Without that, the
Modbus rules load but never match.

## Install into Malcolm

Malcolm loads any `*.rules` file placed in its `suricata/rules/` directory.

```bash
cp <ot-detection-engineering>/deploy/suricata/ot-detection.rules \
   <malcolm>/suricata/rules/ot-detection.rules
cd <malcolm>
docker compose exec -u $(id -u) suricata bash -c \
  'suricata_config_populate.py --suricata /usr/bin/suricata-offline && kill -USR2 $(pidof suricata-offline)'
docker compose exec -u $(id -u) suricata-live bash -c \
  'suricata_config_populate.py --suricata /usr/bin/suricata-offline && kill -USR2 $(pidof suricata)'
```

## Why the previous rules were removed

The former `custom_modbus.rules` used SIDs `1000001-1000003`, which collide with
the NSacyber ELITEWOLF rules Malcolm ships with (`1000000-1001022`), so Suricata
rejected every rule as a duplicate; one rule also used invalid `modbus` syntax.
The canonical ruleset uses the private `9000000-9000099` range and loads cleanly
alongside the defaults.
