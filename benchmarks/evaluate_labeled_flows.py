"""Evaluate flow rules against a caller-supplied labeled CSV corpus.

Input columns: scenario_id, expected_rules, then the normal flow columns.
expected_rules is a semicolon-separated list of rule IDs; leave empty for benign.
Each scenario_id groups flows from one labeled scenario/window. Supply honest
dataset provenance. This tool does not download or fabricate real-world labels.
"""
from __future__ import annotations

import argparse
import csv
import json
import io
from collections import defaultdict
from pathlib import Path

from packetwhisperer.analyzer import analyze_flows, parse_flows

FLOW_COLUMNS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bytes", "packets", "duration",
]


def evaluate_labeled(path: Path, dataset_name: str, provenance: str) -> dict:
    if not dataset_name.strip() or not provenance.strip():
        raise ValueError("dataset-name and provenance must describe the source and labeling method")
    groups = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"scenario_id", "expected_rules", *FLOW_COLUMNS}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
        for line, item in enumerate(reader, start=2):
            scenario_id = (item.get("scenario_id") or "").strip()
            if not scenario_id:
                raise ValueError(f"Line {line}: scenario_id is required")
            expected = {x.strip() for x in (item.get("expected_rules") or "").split(";") if x.strip()}
            if scenario_id in groups and groups[scenario_id]["expected"] != expected:
                raise ValueError(f"Scenario {scenario_id!r} has inconsistent expected_rules labels")
            group = groups.setdefault(scenario_id, {"expected": expected, "rows": []})
            group["rows"].append({key: item[key] for key in FLOW_COLUMNS})
    if not groups:
        raise ValueError("Dataset contains no labeled scenarios")

    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    results = []
    all_rules = set()
    for scenario_id, group in sorted(groups.items()):
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=FLOW_COLUMNS)
        writer.writeheader()
        writer.writerows(group["rows"])
        report = analyze_flows(parse_flows(buffer.getvalue().encode("utf-8")))
        actual, expected = {f["rule_id"] for f in report["findings"]}, group["expected"]
        all_rules |= actual | expected
        results.append({
            "scenario_id": scenario_id, "flow_count": len(group["rows"]),
            "expected_rules": sorted(expected), "actual_rules": sorted(actual),
            "exact_match": actual == expected,
        })
    for rule in sorted(all_rules):
        for group_result in results:
            expected, actual = set(group_result["expected_rules"]), set(group_result["actual_rules"])
            if rule in expected and rule in actual:
                counts[rule]["tp"] += 1
            elif rule in actual:
                counts[rule]["fp"] += 1
            elif rule in expected:
                counts[rule]["fn"] += 1
            else:
                counts[rule]["tn"] += 1
    metrics = {}
    for rule, c in sorted(counts.items()):
        precision = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else 0.0
        recall = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 0.0
        specificity = c["tn"] / (c["tn"] + c["fp"]) if c["tn"] + c["fp"] else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        metrics[rule] = {**c, "precision": round(precision, 4), "recall": round(recall, 4),
                         "specificity": round(specificity, 4), "false_positive_rate": round(1 - specificity, 4),
                         "f1": round(f1, 4)}
    return {
        "benchmark": "labeled-flow-evaluation-v1",
        "dataset_name": dataset_name,
        "provenance": provenance,
        "scenario_count": len(results),
        "flow_count": sum(len(group["rows"]) for group in groups.values()),
        "scenario_results": results,
        "rule_metrics": metrics,
        "exact_match_rate": round(sum(x["exact_match"] for x in results) / len(results), 4),
        "limitations": ["Metrics are only as trustworthy as dataset labels and representativeness.",
                        "Report dataset collection period, environment, class balance, and labeling process alongside results."],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--dataset-name", required=True)
    parser.add_argument("--provenance", required=True, help="Collection source, authorization, date range, and labeling method")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate_labeled(args.input, args.dataset_name, args.provenance)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
