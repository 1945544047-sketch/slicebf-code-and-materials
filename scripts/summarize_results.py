#!/usr/bin/env python3
"""Produce final statistics without treating repeated queries as independent runs.

Raw query files contain the same frozen workload measured in several fresh
processes.  Means and confidence intervals are computed from per-process
workload means; median and P95 describe the complete per-query distribution.
This prevents 80 queries x 5 runs from being reported as 400 independent
experimental repetitions.
"""
import argparse
import csv
import hashlib
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path


QUERY_METRICS = (
    ("total_ms", "total_query_ms", "ms"),
    ("trapdoor_ms", "trapdoor_ms", "ms"),
    ("server_ms", "server_ms", "ms"),
    ("unmask_ms", "unmask_ms", "ms"),
    ("delta_replay_ms", "delta_replay_ms", "ms"),
    ("verify_ms", "verify_ms", "ms"),
    ("client_ms", "client_ms", "ms"),
    ("client_to_server_bytes", "client_to_server_bytes", "bytes"),
    ("server_to_client_bytes", "server_to_client_bytes", "bytes"),
    ("trapdoor_bytes", "trapdoor_bytes", "bytes"),
    ("aggregate_bytes", "aggregate_bytes", "bytes"),
    ("delta_bytes", "delta_bytes", "bytes"),
    ("bucket_bytes", "bucket_bytes", "bytes"),
    ("candidates", "candidate_count", "count"),
)

FIELDS = [
    "experiment", "scheme", "N", "q", "selectivity", "metric", "unit",
    "mean", "median", "p50", "p95", "sd_between_runs", "ci95_low",
    "ci95_high", "ci95_half", "n_runs", "n_measurements", "param1",
    "param2",
]


def percentile(values, probability):
    if not values:
        return math.nan
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = probability * (len(ordered) - 1)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def bootstrap_mean_ci(run_means, label, draws=10000):
    if len(run_means) < 2:
        return "", "", ""
    seed = int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest()[:8],
                          "big")
    rng = random.Random(seed)
    means = []
    for _ in range(draws):
        sample = [run_means[rng.randrange(len(run_means))]
                  for _ in run_means]
        means.append(statistics.fmean(sample))
    low = percentile(means, 0.025)
    high = percentile(means, 0.975)
    return low, high, (high - low) / 2.0


def summarize_group(experiment, scheme, n, q, selectivity, metric, unit,
                    rows, column, param1="", param2=""):
    by_run = defaultdict(list)
    values = []
    for row in rows:
        value = float(row[column])
        values.append(value)
        by_run[int(row["run_id"])].append(value)
    run_means = [statistics.fmean(by_run[run]) for run in sorted(by_run)]
    mean = statistics.fmean(run_means)
    low, high, half = bootstrap_mean_ci(
        run_means, f"{experiment}|{scheme}|{n}|{q}|{selectivity}|{metric}")
    return {
        "experiment": experiment,
        "scheme": scheme,
        "N": n,
        "q": q,
        "selectivity": selectivity,
        "metric": metric,
        "unit": unit,
        "mean": mean,
        "median": statistics.median(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "sd_between_runs": statistics.stdev(run_means)
        if len(run_means) > 1 else "",
        "ci95_low": low,
        "ci95_high": high,
        "ci95_half": half,
        "n_runs": len(run_means),
        "n_measurements": len(values),
        "param1": param1,
        "param2": param2,
    }


def read_rows(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def summarize_queries(results, experiment):
    raw_path = results / experiment / "raw.csv"
    if not raw_path.exists():
        return
    rows = read_rows(raw_path)
    if any(row.get("correct") != "1" for row in rows):
        raise SystemExit(f"correctness failure in {raw_path}")
    output = []
    for column, metric, unit in QUERY_METRICS:
        if not rows or column not in rows[0]:
            continue
        groups = defaultdict(list)
        for row in rows:
            groups[(row["scheme"], int(row["N"]), int(row["q"]),
                    "all")].append(row)
            groups[(row["scheme"], int(row["N"]), int(row["q"]),
                    row["bucket"])].append(row)
        for (scheme, n, q, bucket), selected in sorted(groups.items()):
            # Stage breakdown is emitted only for the all-query workload; the
            # bucket rows are retained for total latency/candidates only.
            if bucket != "all" and metric not in {"total_query_ms",
                                                   "candidate_count"}:
                continue
            output.append(summarize_group(
                experiment, scheme, n, q, bucket, metric, unit, selected,
                column, "network_transport=excluded",
                "ci=bootstrap_over_process_means"))
    write_rows(results / experiment / "summary.csv", output)


def summarize_setup(results):
    raw_path = results / "E3" / "raw.csv"
    if not raw_path.exists():
        return
    rows = read_rows(raw_path)
    output = []
    groups = defaultdict(list)
    for row in rows:
        groups[(row["scheme"], int(row["N"]))].append(row)
    for (scheme, n), selected in sorted(groups.items()):
        output.append(summarize_group(
            "E3", scheme, n, 0, "all", "setup_ms", "ms", selected,
            "setup_ms", "fresh_process_and_fresh_keys",
            "ci=bootstrap_over_process_measurements"))
    write_rows(results / "E3" / "summary.csv", output)


def summarize_updates(results):
    raw_path = results / "E7" / "raw.csv"
    if not raw_path.exists():
        return
    rows = read_rows(raw_path)
    if any(row.get("correct") != "1" for row in rows):
        raise SystemExit(f"correctness failure in {raw_path}")
    output = []
    groups = defaultdict(list)
    for row in rows:
        groups[(row["scheme"], int(row["N"]), row["operation"])].append(row)
    for (scheme, n, operation), selected in sorted(groups.items()):
        output.append(summarize_group(
            "E7", scheme, n, 0, "all", f"{operation}_ms", "ms", selected,
            "total_ms", "one_fixed_update_trace",
            "one_cycle=one_delete+one_insert"))
    write_rows(results / "E7" / "summary.csv", output)


def summarize_first_after_update(results):
    raw_path = results / "E8" / "raw.csv"
    if not raw_path.exists():
        return
    rows = read_rows(raw_path)
    if any(row.get("correct") != "1" for row in rows):
        raise SystemExit(f"correctness failure in {raw_path}")
    output = []
    for column, metric in (
            ("batch_update_ms", "batch_update_ms"),
            ("first_query_ms", "first_query_ms")):
        groups = defaultdict(list)
        for row in rows:
            groups[(row["scheme"], int(row["N"]),
                    row["operation"])].append(row)
        for (scheme, n, operation), selected in sorted(groups.items()):
            output.append(summarize_group(
                "E8", scheme, n, 3, operation, metric, "ms", selected,
                column, "scenario=first_after_update",
                "one_cycle=one_document_delete_or_insert"))
    write_rows(results / "E8" / "summary.csv", output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    args = parser.parse_args()
    results = Path(args.results)
    summarize_queries(results, "E1")
    summarize_queries(results, "E2")
    summarize_setup(results)
    summarize_updates(results)
    summarize_first_after_update(results)
    print(f"[summary] process-aware summaries written under {results}")


if __name__ == "__main__":
    main()
