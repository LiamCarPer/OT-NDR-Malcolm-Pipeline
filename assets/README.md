# Demo assets

| File | What it is |
| :--- | :--- |
| `pipeline_demo.cast` | The raw asciinema recording of the walkthrough. Timing-accurate, playable with `asciinema play assets/pipeline_demo.cast`. |
| `pipeline_demo.gif` | The cast rendered to an animation for the README. |
| `pipeline_demo.mp4` | The same animation at higher quality. |
| `render_cast.py` | Replays the cast through a terminal emulator (pyte) and draws the GIF and MP4. |

## What the demo shows

A real run against the committed captures, in four steps:

1. **Alert-triggered triage** — `setpoint_write.pcap` is ingested because the
   committed Suricata evidence says SID 9000001 fired on it. The report names the
   alert, the severity basis and the change-window status.
2. **The same detection in a different context** — `setpoint_write_maintenance.pcap`
   fires the same rule, and comes out one severity lower because an approved
   change window covers the event time.
3. **The custody record** — the audit log line for that ingest, carrying the
   trigger and the detections so the quality metric can join on them.
4. **Detection quality** — `automation/detection_quality.py` computes correctness
   and actionability per detection from the recorded dispositions.

## How it was recorded

```bash
export MALCOLM_PCAP_DIR=/tmp/ot-ndr-demo/malcolm
asciinema rec --overwrite --cols 120 --rows 36 -c "bash demo.sh" assets/pipeline_demo.cast
python3 assets/render_cast.py
```

The recording runs against the real repository, so it appends to
`automation/ingest_audit.log` and generates reports under `incident-response/`.
Both are reverted afterwards so the committed audit record stays the canonical
one. If you re-record, revert them the same way.

## What the demo does not show

The rule firing is read from committed evidence
(`detection-engineering/evidence/`), produced by
`detection-engineering/suricata_check.py`, not from a live Malcolm instance. The
demo proves the pipeline, the ruleset and the triage loop agree on the same
bytes; it does not prove a Malcolm deployment is running.
