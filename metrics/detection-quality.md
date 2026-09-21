# Detection quality

Derived from `automation/ingest_audit.log` (what fired, per committed capture)
and `automation/dispositions.jsonl` (what an analyst decided). Regenerate with:

```bash
python3 automation/detection_quality.py
```

## How to read the two rates

- **Correctness** — did the detection fire on the behaviour it describes?
  `(true positives + expected changes) / (those + false positives)`.
- **Actionability** — was it worth an analyst's time? `true positives / resolved`.
  A detection can be perfectly correct and still be noise, which is what this
  second rate exists to expose.

Duplicates and inconclusive outcomes are counted but excluded from both rates.
The unit of triage is the capture, so every detection that fired on it inherits
the outcome; re-triaging a capture appends a record and the latest wins.

## Disposition types

| Disposition | Meaning |
| :--- | :--- |
| `true_positive` | The detection described a real event that warranted action. |
| `expected_change` | The event was real and covered by an approved change or known activity. |
| `benign` | Normal operations for an informational finding: correct, but not actionable. |
| `false_positive` | The detection fired on traffic it does not describe. |
| `duplicate` | The same event had already been triaged. |
| `inconclusive` | Not enough information to decide. |

## Per detection

| Detection | Fired in | Reviewed | TP | Expected | Benign | FP | Dup | Unresolved | Correctness | Actionability |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `dpi:drift` | `baseline_modbus.pcap` | 1/1 | 0 | 0 | 1 | 0 | 0 | 0 | — | 0% |
| `dpi:read_fanout` | `modbus_recon_fanout.pcap` | 1/1 | 1 | 0 | 0 | 0 | 0 | 0 | 100% | 100% |
| `dpi:setpoint_write` | `setpoint_write.pcap`, `setpoint_write_maintenance.pcap` | 2/2 | 1 | 1 | 0 | 0 | 0 | 0 | 100% | 50% |
| `sid:9000001` | `setpoint_write.pcap`, `setpoint_write_maintenance.pcap` | 2/2 | 1 | 1 | 0 | 0 | 0 | 0 | 100% | 50% |

## Tuning actions

- **dpi:drift** fired on normal operations. Scope it: register the source in the asset model, or suppress the finding for pollers that are known and expected.
- **dpi:setpoint_write** fired on approved work, so the detection is right and the context was the problem. Decide whether it should still page now that the change calendar lowers the severity, and add the source to the write allowlist if approved changes are performed through approved tooling.
- **sid:9000001** fired on approved work, so the detection is right and the context was the problem. Decide whether it should still page now that the change calendar lowers the severity, and add the source to the write allowlist if approved changes are performed through approved tooling.

## What this does not tell you

- The corpus is 4 committed captures in a lab. The rates are a
  demonstration of the loop, not statistics.
- The dispositions are the author's own triage of lab evidence (2026-09-21 to 2026-09-21), not independent
  ground truth. A real programme needs analysts who are not the detection author.
- A detection with no dispositions is not evidence of quality. It is an unread queue,
  which is why the unreviewed count appears in the tuning actions rather than hidden.
