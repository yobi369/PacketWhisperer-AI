"""Reproducible sanity benchmark; synthetic data is not real-world validation."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from packetwhisperer.analyzer import analyze_flows, parse_flows

HEADER = b"src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,duration\n"


def row(src: str, dst: str, sport: int, dport: int, size: int = 1200) -> bytes:
    return f"{src},{dst},{sport},{dport},TCP,{size},10,0.5\n".encode()


def scenarios():
    return {
        "benign_small_client": {
            "csv": HEADER + b"".join(row("10.0.0.10", f"10.0.1.{i}", 51000 + i, 443) for i in range(1, 4)),
            "expected_rules": set(),
        },
        "synthetic_destination_sweep": {
            "csv": HEADER + b"".join(row("10.0.0.20", f"10.0.2.{i}", 52000 + i, 443) for i in range(1, 26)),
            "expected_rules": {"FLOW-HIGH-FANOUT"},
        },
        "synthetic_large_transfer": {
            "csv": HEADER + row("10.0.0.30", "10.0.3.10", 53000, 443, 75_000_000),
            "expected_rules": {"FLOW-LARGE-TRANSFER"},
        },
    }


def evaluate() -> dict:
    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    scenario_results = []
    for name, case in scenarios().items():
        report = analyze_flows(parse_flows(case["csv"]))
        actual = {item["rule_id"] for item in report["findings"]}
        expected = case["expected_rules"]
        rules = actual | expected
        for rule in rules:
            if rule in actual and rule in expected:
                counts[rule]["tp"] += 1
            elif rule in actual:
                counts[rule]["fp"] += 1
            else:
                counts[rule]["fn"] += 1
        scenario_results.append({
            "scenario": name,
            "expected_rules": sorted(expected),
            "actual_rules": sorted(actual),
            "passed": actual == expected,
        })
    metrics = {}
    for rule, c in sorted(counts.items()):
        precision = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else 1.0
        recall = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 1.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        metrics[rule] = {**c, "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}
    return {
        "benchmark": "synthetic-rule-sanity-v1",
        "dataset": "generated-in-memory",
        "scenarios": scenario_results,
        "rule_metrics": metrics,
        "all_scenarios_passed": all(item["passed"] for item in scenario_results),
        "limitations": [
            "Synthetic cases validate deterministic rule behavior only.",
            "These scores are not estimates of production precision, recall, or false-positive rate.",
            "Real-world evaluation requires representative labeled benign and malicious captures.",
        ],
    }


def main() -> None:
    result = evaluate()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["all_scenarios_passed"] else 1)


if __name__ == "__main__":
    main()
