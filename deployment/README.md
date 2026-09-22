# Deployment

How to put this pipeline next to a live sensor, and what is proven versus what
you have to check on your own installation.

Everything here is configuration and packaging around two components that
already exist: **Malcolm** captures and analyses traffic, and
**`automation/malcolm_ingest.py`** profiles the captures, enriches them with
asset context and writes the reports. Neither is modified.

## How the pieces fit

```
plant network ──► SPAN / TAP ──► PCAP_IFACE
                                      │
                                  Malcolm
                                      │  rotates every PCAP_ROTATE_MINUTES
                                      ▼
                            <malcolm>/pcap/*.pcap          ← MALCOLM_PCAP_DIR
                                      │
                       malcolm_ingest.py --watch (systemd or compose)
                                      │
                    DPI ──► asset + change-window context ──► report
                                      │
                          automation/ingest_audit.log (JSONL)
                                      │
                       automation/detection_quality.py ──► metrics/
```

The two paths that must agree are `<malcolm>/pcap` and `MALCOLM_PCAP_DIR`.
When they are the same directory the pipeline recognises a capture that is
already in place instead of trying to copy it onto itself, which is the deployed
shape; when they differ it copies, which is the offline shape used for the
committed captures.

## 1. Sensor configuration

Append the fragments to Malcolm's environment files:

```bash
cat deployment/malcolm/config/suricata.env.fragment    >> <malcolm>/config/suricata.env
cat deployment/malcolm/config/pcap-capture.env.fragment >> <malcolm>/config/pcap-capture.env
$EDITOR <malcolm>/config/pcap-capture.env      # set PCAP_IFACE to the mirrored interface
cd <malcolm> && docker compose up -d --force-recreate suricata suricata-live pcap-capture
```

**Why these settings matter, and the one that will bite you.** The Suricata rule
keyword `modbus: function 6` matches nothing unless the Modbus application-layer
parser is enabled — the rules load, no error is logged, and the sensor detects
nothing. Malcolm enables the parsers but disables their EVE event types by
default, and it exposes `SURICATA_DISABLE_ICS_ALL` as a master switch that turns
every ICS parser off at once. `deployment/verify_deployment.py` proves the
load-bearing part: with the parser disabled the write capture produces zero
alerts, with it enabled it produces SID 9000001.

### Placement

Use a passive tap or a SPAN/mirror port. The sensor must not be in the traffic
path and must not transmit on the OT segment.

| Option | `PCAP_IFACE` | Notes |
| :--- | :--- | :--- |
| Span/mirror port | the mirror destination interface | Simplest; the switch does the copying |
| Network tap | the monitor-side tap interface | One-way by construction |
| Aggregated spans | `eth1,eth2` | When one interface cannot carry the link |

Restrict the capture so the sensor is not filling disks with everything else:

```bash
PCAP_FILTER=tcp port 502 or tcp port 20000 or tcp port 4840 or tcp port 102
```

## 2. The pipeline as a service

It watches for rotated captures and ingests each one exactly once: a capture
whose SHA-256 is already in the audit log is skipped, so restarting the service
does not re-ingest the estate, and a file whose size is still changing is left
for the next pass.

### systemd (OT appliance shape)

```bash
sudo useradd --system --home /opt/ot-ndr ot-ndr
sudo git clone <repo> /opt/ot-ndr
sudo pip3 install -r /opt/ot-ndr/automation/requirements.txt   # pytest, flake8: not needed at runtime
sudo apt-get install -y tshark                                  # required: the DPI profiler reads it
sudo cp deployment/systemd/ot-ndr-ingest.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ot-ndr-ingest
journalctl -u ot-ndr-ingest -f
```

The unit runs `--watch`, restarts on failure, and sets `MALCOLM_PCAP_DIR` to the
same directory it watches. Reports and the audit log are written into
`/opt/ot-ndr`, which is the only path the unit can write to.

### Docker Compose (beside Malcolm)

```bash
cd <repo>
MALCOLM_PCAP_HOST_DIR=<malcolm>/pcap \
  docker compose -f deployment/docker/docker-compose.ot-ndr.yml up -d --build
docker compose -f deployment/docker/docker-compose.ot-ndr.yml logs -f
```

It runs as your uid, mounts the repository read-write (reports and the audit log
live there) and Malcolm's capture directory read-only.

## 3. Verification

### What is proven offline

```bash
python deployment/verify_deployment.py --malcolm ../Malcolm
```

Two checks, each writing evidence under `deployment/evidence/`:

- **`app-layer`** — runs Suricata over the committed write capture with the
  Modbus parser disabled and enabled, and records the difference. This is the
  claim that a sensor missing the setting looks healthy and detects nothing.
- **`malcolm-config`** — checks every variable the fragments set against the
  Malcolm checkout: that a component there actually reads it, and that the ICS
  variables are the ones the Suricata generator uses to gate parsing and EVE
  output. It is static, and says so.

`automation/tests/test_deployment.py` fails if a fragment changes without the
evidence being regenerated, so the two cannot drift.

### What you have to check on your installation

The lab cannot verify a running Malcolm or your switch. On the sensor:

```bash
# 1. ICS parsing is not switched off
grep -E 'DISABLE_ICS_ALL|MODBUS_ENABLED|MODBUS_EVE_ENABLED' <malcolm>/config/suricata.env

# 2. captures are actually arriving
ls -l <malcolm>/pcap

# 3. an alert carries its protocol detail
docker compose -f <malcolm>/docker-compose.yml exec suricata \
  bash -c 'grep -m1 "\"event_type\":\"alert\"" /data/suricata/eve.json'  # expect a "modbus":{...} block
```

On the pipeline: the first capture to arrive should log `New capture:`, a
severity, and `Forensic report generated:`; the same capture on a later pass logs
`Already ingested, skipping:`.

## 4. Operations

- **Re-ingest a capture deliberately.** Idempotency applies to watch mode, not
  to `--file`, which is what the offline regeneration steps use. To rebuild
  everything, re-run the commands in `pcaps/README.md`.
- **Change detection content.** The rules live in
  `ot-detection-engineering`; the install and reload steps are in
  `detection-engineering/README.md`. Nothing in this deployment needs to change.
- **Triage.** Record the outcome so the metric reflects it:
  `python3 automation/detection_quality.py --record --capture <name> ...`
- **Upgrade.** `git pull`, reinstall nothing, restart the unit. The audit log is
  append-only and the metric is derived, so no state has to be migrated.

## 5. Rollback

Stop the unit and revert the two environment fragments. Malcolm keeps working:
the fragments only add parsing and logging, and nothing in this repository is
required for Malcolm to run.

## What this does not prove

- **No physical sensor.** The configuration is real and verified against
  Malcolm's own components; the traffic is committed lab captures, and the
  interface path (`PCAP_IFACE`) is documented rather than exercised.
- **No plant.** The assets, criticality and change windows come from
  `automation/asset_inventory.json` and `automation/change_windows.json`, which
  are hand-written lab fixtures. In a deployment they come from a CMDB and the
  change calendar.
- **No high availability or queueing.** One watcher, one host: a capture that
  arrives while the service is down is picked up on restart, and nothing is
  buffered anywhere else.
