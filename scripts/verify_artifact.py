"""Read-only checks of workload hashes, experiment coverage and finite raw values."""
import csv
from collections import defaultdict
import gzip
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMES = {"SliceBF", "Doris", "XEBFF-Conj", "Ren"}


def check_raw(path, experiment, campaign):
    counts = defaultdict(int)
    measured_queries = defaultdict(list)
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    allowed = SCHEMES if campaign == "main" else {
        "SliceBF", "SliceBF-NoMask", "SliceBF-NoBitSlice", "SliceBF-NoPruning"}
    if experiment == "E8":
        allowed = {"SliceBF", "Ren"}
    for line, row in enumerate(rows, 2):
        if row["scheme"] not in allowed:
            raise ValueError(f"Unexpected scheme: {path}:{line}")
        for flag in ("correct", "success"):
            if flag in row and row[flag] != "1":
                raise ValueError(f"Failed {flag}: {path}:{line}")
        for field, value in row.items():
            if value and (field.endswith("_ms") or field.endswith("_bytes")):
                if not math.isfinite(float(value)) or float(value) < 0:
                    raise ValueError(f"Invalid {field}: {path}:{line}")
        key = (row["scheme"], int(row["N"]), int(row.get("q", "0")),
               row.get("run_id", ""), row.get("operation", ""))
        counts[key] += 1
        if experiment in {"E1", "E2"}:
            measured_queries[key].append(row["query_id"])
    expected_unit = 80 if experiment in {"E1", "E2"} else 100 if experiment == "E8" else 1
    if set(counts.values()) != {expected_unit}:
        raise ValueError(f"Wrong observations per unit: {path}: {set(counts.values())}")
    expected_rows = {"E1": 9600, "E2": 6400, "E3": 150, "E4": 24, "E8": 12000}
    expected = 1600 if campaign == "ablation" else expected_rows[experiment]
    if len(rows) != expected:
        raise ValueError(f"Unexpected rows in {path}: {len(rows)} != {expected}")
    # Assert every planned scale/scheme/run/arity/operation is present, not only a total count.
    scales = [300000] if campaign == "ablation" or experiment == "E2" else [50000,100000,150000,200000,250000,300000]
    wanted = set()
    for scheme in allowed:
        run_ids = ["0"] if experiment == "E4" else [str(n) for n in range(10 if scheme == "Doris" and experiment == "E3" else 5)]
        for n in scales:
            for q in ([2,3,4,5] if experiment == "E2" else [3] if experiment in {"E1","E8"} else [0]):
                for run in run_ids:
                    for operation in (["delete","insert"] if experiment == "E8" else [""]):
                        wanted.add((scheme,n,q,run,operation))
    if set(counts) != wanted:
        raise ValueError(f"Coverage mismatch: {path}: missing={len(wanted-set(counts))}, extra={len(set(counts)-wanted)}")
    for key, ids in measured_queries.items():
        q = key[2]
        frozen = [json.loads(line)["query_id"] for line in
                  (ROOT / "data/queries" / f"q{q}_80.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        if len(set(ids)) != len(ids) or set(ids) != set(frozen):
            raise ValueError(f"Query workload coverage mismatch: {path}: {key}")
    return len(rows)


def main():
    checksums = ROOT / "CHECKSUMS.sha256"
    if checksums.exists():
        for line in checksums.read_text(encoding="utf-8").splitlines():
            expected, name = line.split("  ", 1)
            h = hashlib.sha256()
            with (ROOT / name).open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(chunk)
            if h.hexdigest() != expected:
                raise ValueError(f"Package file hash mismatch: {name}")
    manifest = json.loads((ROOT / "data/original_manifest.json").read_text(encoding="utf-8"))
    h = hashlib.sha256()
    with gzip.open(ROOT / "data/frozen/corpus_N300000.jsonl.gz", "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    if h.hexdigest() != manifest["corpora"]["N300000"]["sha256"]:
        raise ValueError("Frozen corpus hash mismatch")
    for name, item in manifest["query_workload"]["files"].items():
        actual = hashlib.sha256((ROOT / "data/queries" / name).read_bytes()).hexdigest()
        if actual != item["sha256"]:
            raise ValueError(f"Query/oracle hash mismatch: {name}")
    rows = {}
    for campaign in ("main", "ablation"):
        for path in sorted((ROOT / "results" / campaign).glob("E*/raw.csv")):
            key = path.relative_to(ROOT).as_posix()
            rows[key] = check_raw(path, path.parent.name, campaign)
    print(json.dumps({"status":"PASS", "frozen_corpus_and_queries":"SHA-256 verified", "raw_rows":rows,
                      "note":"These checks do not certify code ownership, security proofs or full benchmark reruns."}, indent=2))


if __name__ == "__main__":
    main()
