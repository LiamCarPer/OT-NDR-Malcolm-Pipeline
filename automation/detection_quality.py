#!/usr/bin/env python3
r"""
Detection quality: turn analyst dispositions into per-detection metrics.

A detection that nobody dispositions is a detection nobody has checked. This
tool closes the loop between what fired and what an analyst decided:

    python3 automation/detection_quality.py --record \\
        --capture setpoint_write.pcap --disposition true_positive \\
        --note "unauthorised setpoint write"

    python3 automation/detection_quality.py        # compute and write the report

The unit of triage is the **event**, not the individual rule: an analyst
dispositions a capture, and every detection that fired on it inherits the
outcome. That is how a SOC queue actually works, and it means a corroborating
finding cannot be counted as an unread alert just because the rule was the thing
that paged. One capture has one current disposition; re-triaging appends a newer
record and the latest wins.

Two rates are reported per detection, because they answer different questions:

- **Correctness** - did the detection fire on the behaviour it describes?
  Driven by true positives, expected changes and false positives.
- **Actionability** - was it worth an analyst's time? Driven by true positives
  only. A rule can be perfectly correct and still be noise.

Duplicates and inconclusive outcomes are counted but excluded from both rates.
The metric is derived from committed data (the audit log and the disposition
file), so it cannot drift from the evidence the way a hand-written number can.

Author: Liam Carvajal (@LiamCarPer)
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
AUDIT_LOG = os.path.join(SCRIPT_DIR, "ingest_audit.log")
DISPOSITIONS = os.path.join(SCRIPT_DIR, "dispositions.jsonl")
PCAP_SOURCE = os.path.join(PROJECT_DIR, "pcaps")
OUTPUT = os.path.join(PROJECT_DIR, "metrics", "detection-quality.md")

# What an analyst can decide, and what each decision means for the metrics.
DISPOSITION_TYPES = {
    "true_positive": "The detection described a real event that warranted action.",
    "expected_change": "The event was real and covered by an approved change or known activity.",
    "false_positive": "The detection fired on traffic it does not describe.",
    "benign": "Normal operations for an informational finding: correct, but not actionable.",
    "duplicate": "The same event had already been triaged.",
    "inconclusive": "Not enough information to decide.",
}
CORRECT = {"true_positive", "expected_change"}
TO_PRESENT = [
    "true_positive", "expected_change", "benign",
    "false_positive", "duplicate", "inconclusive",
]


def load_jsonl(path):
    """Read a JSONL file, skipping blank lines and reporting unreadable ones."""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                print(
                    f"warning: {os.path.basename(path)} line {number} is not JSON",
                    file=sys.stderr,
                )
    return rows


def fired_in():
    """
    Map each detection key to the committed captures that triggered it.

    The audit log is the record of what fired. Counting *captures* rather than
    log lines keeps a re-ingested capture from inflating the denominator.
    """
    fired = {}
    for entry in load_jsonl(AUDIT_LOG):
        for key in entry.get("detections", []):
            fired.setdefault(key, set()).add(entry.get("file", "unknown"))
    return fired


def current_dispositions():
    """Resolve one disposition per capture, latest record winning."""
    resolved = {}
    for row in load_jsonl(DISPOSITIONS):
        capture = row.get("capture")
        if not capture:
            continue
        previous = resolved.get(capture)
        if previous is None or row.get("timestamp", "") >= previous.get("timestamp", ""):
            resolved[capture] = row
    return resolved


def rate(numerator, denominator):
    """Format a rate, or an em dash when nothing resolved."""
    if denominator == 0:
        return "—"
    return f"{numerator / denominator * 100:.0f}%"


def compute():
    """Join what fired with what an analyst decided, per detection."""
    fired = fired_in()
    decisions = current_dispositions()

    rows = []
    for key in sorted(fired):
        captures = sorted(fired[key])
        decided = [decisions[name] for name in captures if name in decisions]
        counts = Counter(row.get("disposition") for row in decided)

        correct_denominator = sum(counts[name] for name in CORRECT) + counts["false_positive"]
        actionable_denominator = (
            sum(counts[name] for name in CORRECT)
            + counts["benign"]
            + counts["false_positive"]
        )

        rows.append(
            {
                "detection": key,
                "triggers": captures,
                "reviewed": len(decided),
                "unreviewed": len(captures) - len(decided),
                "counts": counts,
                "correctness": rate(sum(counts[name] for name in CORRECT), correct_denominator),
                "actionability": rate(counts["true_positive"], actionable_denominator),
            }
        )
    return rows, decisions


def tuning_actions(rows):
    """Say what to do about each detection that is not pulling its weight."""
    actions = []
    for row in rows:
        counts, key = row["counts"], row["detection"]
        if counts["false_positive"]:
            actions.append(
                f"**{key}** fired on traffic it does not describe. Fix the detection logic."
            )
        if counts["benign"]:
            actions.append(
                f"**{key}** fired on normal operations. Scope it: register the source in the "
                "asset model, or suppress the finding for pollers that are known and expected."
            )
        if counts["expected_change"]:
            actions.append(
                f"**{key}** fired on approved work, so the detection is right and the context "
                "was the problem. Decide whether it should still page now that the change "
                "calendar lowers the severity, and add the source to the write allowlist if "
                "approved changes are performed through approved tooling."
            )
        if row["unreviewed"]:
            actions.append(
                f"**{key}** has {row['unreviewed']} triggering capture(s) with no disposition. "
                "Triage them or the metric is measuring an unread queue."
            )
    return actions


def render(rows, decisions):
    """Render the committed quality report."""
    lines = [
        "# Detection quality",
        "",
        "Derived from `automation/ingest_audit.log` (what fired, per committed capture)",
        "and `automation/dispositions.jsonl` (what an analyst decided). Regenerate with:",
        "",
        "```bash",
        "python3 automation/detection_quality.py",
        "```",
        "",
        "## How to read the two rates",
        "",
        "- **Correctness** — did the detection fire on the behaviour it describes?",
        "  `(true positives + expected changes) / (those + false positives)`.",
        "- **Actionability** — was it worth an analyst's time? `true positives / resolved`.",
        "  A detection can be perfectly correct and still be noise, which is what this",
        "  second rate exists to expose.",
        "",
        "Duplicates and inconclusive outcomes are counted but excluded from both rates.",
        "The unit of triage is the capture, so every detection that fired on it inherits",
        "the outcome; re-triaging a capture appends a record and the latest wins.",
        "",
        "## Disposition types",
        "",
        "| Disposition | Meaning |",
        "| :--- | :--- |",
    ]
    for name in TO_PRESENT:
        lines.append(f"| `{name}` | {DISPOSITION_TYPES[name]} |")

    lines += [
        "",
        "## Per detection",
        "",
        "| Detection | Fired in | Reviewed | TP | Expected | Benign | FP | Dup "
        "| Unresolved | Correctness | Actionability |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    captures_in_corpus = set()
    for row in rows:
        captures_in_corpus.update(row["triggers"])
        counts, fired = row["counts"], ", ".join(f"`{name}`" for name in row["triggers"])
        lines.append(
            f"| `{row['detection']}` | {fired} | {row['reviewed']}/{len(row['triggers'])} | "
            f"{counts['true_positive']} | {counts['expected_change']} | {counts['benign']} | "
            f"{counts['false_positive']} | {counts['duplicate']} | {counts['inconclusive']} | "
            f"{row['correctness']} | {row['actionability']} |"
        )

    actions = tuning_actions(rows)
    lines += ["", "## Tuning actions", ""]
    lines += [f"- {action}" for action in actions] if actions else ["- Nothing outstanding."]

    dates = sorted(row["timestamp"][:10] for row in decisions.values() if row.get("timestamp"))
    span = f"{dates[0]} to {dates[-1]}" if dates else "no dispositions recorded"

    lines += [
        "",
        "## What this does not tell you",
        "",
        f"- The corpus is {len(captures_in_corpus)} committed captures in a lab. The rates are a",
        "  demonstration of the loop, not statistics.",
        f"- The dispositions are the author's own triage of lab evidence ({span}), not independent",
        "  ground truth. A real programme needs analysts who are not the detection author.",
        "- A detection with no dispositions is not evidence of quality. It is an unread queue,",
        "  which is why the unreviewed count appears in the tuning actions rather than hidden.",
        "",
    ]
    return "\n".join(lines)


def record(args):
    """Append one analyst disposition, validated against the audit log."""
    if args.disposition not in DISPOSITION_TYPES:
        print(f"unknown disposition: {args.disposition}", file=sys.stderr)
        print(f"valid: {', '.join(TO_PRESENT)}", file=sys.stderr)
        return 1

    if not os.path.exists(os.path.join(PCAP_SOURCE, args.capture)):
        print(f"not a committed capture: {args.capture}", file=sys.stderr)
        return 1

    fired = fired_in()
    covered = sorted(key for key, captures in fired.items() if args.capture in captures)
    if not covered:
        print(f"{args.capture} has no detections in {os.path.basename(AUDIT_LOG)}", file=sys.stderr)
        return 1

    entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "capture": args.capture,
        "detections": covered,
        "disposition": args.disposition,
        "analyst": args.analyst,
        "note": args.note or "",
    }
    with open(DISPOSITIONS, "a") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"Recorded {args.disposition} for {args.capture} ({', '.join(covered)}).")
    print("Regenerate the metric with: python3 automation/detection_quality.py")
    return 0


def main():
    """Record a disposition, or compute and write the quality report."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--record", action="store_true", help="append a disposition")
    parser.add_argument("--capture", help="capture the disposition is about")
    parser.add_argument("--disposition", help="one of: " + ", ".join(TO_PRESENT))
    parser.add_argument("--analyst", default="Liam Carvajal", help="who decided")
    parser.add_argument("--note", help="why")

    args = parser.parse_args()

    if args.record:
        missing = [name for name in ("capture", "disposition") if not getattr(args, name)]
        if missing:
            parser.error("--record needs " + ", ".join("--" + name for name in missing))
        return record(args)

    rows, decisions = compute()
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w") as f:
        f.write(render(rows, decisions))

    for row in rows:
        counts = row["counts"]
        print(
            f"{row['detection']:<18} triggers={len(row['triggers'])} "
            f"reviewed={row['reviewed']} tp={counts['true_positive']} "
            f"expected={counts['expected_change']} benign={counts['benign']} "
            f"fp={counts['false_positive']} "
            f"correctness={row['correctness']} actionability={row['actionability']}"
        )
    print(f"Wrote {os.path.relpath(OUTPUT, PROJECT_DIR)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
