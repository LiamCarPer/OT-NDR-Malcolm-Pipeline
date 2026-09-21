# Demo assets

| File | What it is |
| :--- | :--- |
| `pipeline_demo.cast` | The raw asciinema recording of the walkthrough. Timing-accurate, playable with `asciinema play assets/pipeline_demo.cast`. |
| `pipeline_demo.gif` | The cast rendered to an animation for the README. |
| `pipeline_demo.mp4` | The same animation at higher quality. |
| `render_cast.py` | Replays the cast through a terminal emulator (pyte) and draws the GIF and MP4. |

## What the demo shows

A real run of `automation/malcolm_ingest.py` against the committed captures, in
four steps:

1. `baseline_modbus.pcap` — 610 reads, no control operation, no technique asserted.
2. `setpoint_write.pcap` — one control operation, CRITICAL report generated.
3. The append-only audit log, one JSON object per ingestion.
4. The same bytes against the generated Suricata ruleset: SID 9000001 fires.

## How it was recorded

```bash
export MALCOLM_PCAP_DIR=/tmp/ot-ndr-demo/malcolm
asciinema rec --overwrite --cols 120 --rows 30 -c "bash demo.sh" assets/pipeline_demo.cast
python3 assets/render_cast.py
```

The recording runs against the real repository, so it appends to
`automation/ingest_audit.log` and generates a report under `incident-response/`.
Both are reverted afterwards so the committed audit record stays the canonical
one. If you re-record, revert them the same way.

## What the demo does not show

The rule firing is read from committed evidence
(`detection-engineering/evidence/setpoint_write.json`) produced by
`detection-engineering/suricata_check.py`, not from a live Malcolm instance. The
demo proves the pipeline and the ruleset agree on the same bytes; it does not
prove a Malcolm deployment is running.
