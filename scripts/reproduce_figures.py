"""Recompute statistics and the four paper figures, without rerunning timings."""
import argparse
import csv
import math
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compare_csv(expected, actual):
    def read(path):
        with path.open(encoding="utf-8-sig", newline="") as stream:
            return list(csv.DictReader(stream))
    old, new = read(expected), read(actual)
    if len(old) != len(new):
        raise ValueError(f"Summary row count differs: {expected}")
    for index, (a, b) in enumerate(zip(old, new), 2):
        if a.keys() != b.keys():
            raise ValueError(f"Summary columns differ: {expected}")
        for key in a:
            if a[key] == b[key]:
                continue
            try:
                x, y = float(a[key]), float(b[key])
            except ValueError:
                raise ValueError(f"Summary differs: {expected}:{index} {key}") from None
            if not math.isclose(x, y, rel_tol=1e-10, abs_tol=1e-10):
                raise ValueError(f"Summary differs: {expected}:{index} {key}: {x} != {y}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "work/reproduced")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        raise SystemExit("Output already exists; choose a new --out directory.")
    for campaign in ("main", "ablation"):
        target = out / campaign
        shutil.copytree(ROOT / "results" / campaign, target)
        subprocess.run([sys.executable, str(ROOT / "scripts/summarize_results.py"),
                        "--results", str(target)], check=True)
        for summary in sorted(target.glob("E*/summary.csv")):
            compare_csv(ROOT / "results" / campaign / summary.relative_to(target), summary)
        print(f"{campaign}: saved and recomputed summaries agree", flush=True)
    import matplotlib
    matplotlib.use("Agg")
    import plot_results
    import plot_slicebf_ablation
    figures = out / "figures"
    figures.mkdir()
    plot_results.plot_query(out / "main", figures)
    plot_results.plot_setup_storage(out / "main", figures)
    plot_results.plot_dynamic(out / "main", figures)
    plot_slicebf_ablation.plot(out / "ablation/E1/summary.csv", figures)
    print(f"Four experimental figures reproduced: {figures}")
    print("PDF metadata/font differences can change file hashes; numerical inputs were checked.")


if __name__ == "__main__":
    main()
