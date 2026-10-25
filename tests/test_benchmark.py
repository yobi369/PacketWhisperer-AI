from packetwhisperer.benchmark import evaluate


def test_synthetic_benchmark_cases_are_reproducible():
    report = evaluate()
    assert report["all_scenarios_passed"] is True
    assert len(report["scenarios"]) == 3
    assert all(item["passed"] for item in report["scenarios"])
    assert all("precision" in metric and "recall" in metric for metric in report["rule_metrics"].values())
