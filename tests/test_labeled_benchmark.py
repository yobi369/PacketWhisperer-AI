import csv

from benchmarks.evaluate_labeled_flows import evaluate_labeled


def test_labeled_benchmark_reports_provenance_and_metrics(tmp_path):
    path = tmp_path / "labeled.csv"
    columns = ["scenario_id", "expected_rules", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes", "packets", "duration"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerow({
            "scenario_id": "benign", "expected_rules": "", "src_ip": "10.0.0.1",
            "dst_ip": "10.0.1.1", "src_port": 51000, "dst_port": 443,
            "protocol": "TCP", "bytes": 1200, "packets": 10, "duration": 0.5,
        })
        for i in range(1, 26):
            writer.writerow({
                "scenario_id": "sweep", "expected_rules": "FLOW-HIGH-FANOUT",
                "src_ip": "10.0.0.20", "dst_ip": f"10.0.2.{i}",
                "src_port": 52000 + i, "dst_port": 443, "protocol": "TCP",
                "bytes": 1200, "packets": 10, "duration": 0.5,
            })
    report = evaluate_labeled(path, "controlled-lab-v1", "authorized lab, manually labeled by scenario")
    assert report["scenario_count"] == 2
    assert report["flow_count"] == 26
    assert report["dataset_name"] == "controlled-lab-v1"
    assert report["rule_metrics"]["FLOW-HIGH-FANOUT"]["tp"] == 1
    assert report["rule_metrics"]["FLOW-HIGH-FANOUT"]["fp"] == 0
