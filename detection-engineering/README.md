# Detection engineering

The Suricata ruleset this pipeline runs is generated and validated in
[ot-detection-engineering](https://github.com/LiamCarPer/ot-detection-engineering).
It is not maintained here, so the two repositories cannot drift apart.

- **Canonical rules:** `rules/native/suricata/*.rules` in that repository.
- **Generated artifact:** `deploy/suricata/ot-detection.rules` (24 rules, SIDs
  `9000001-9000028`) covering Modbus, DNP3, OPC UA and S7comm.
- **Validation:** `make suricata-check` runs the rules over committed captures,
  and `tools/malcolm_check.py` runs them inside a Malcolm installation with the
  default ruleset enabled; both commit their evidence under `deploy/evidence/`.

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
