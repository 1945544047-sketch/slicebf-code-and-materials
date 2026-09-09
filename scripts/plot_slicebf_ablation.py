#!/usr/bin/env python3
"""Render the measured NSF-300K SliceBF ablation as a PBKS-style bar chart."""
import argparse
import csv
import math
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import AutoMinorLocator


plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "mathtext.fontset": "stix",
    # The PDF is scaled to one-column width in LaTeX; use source sizes that
    # remain legible after scaling.
    "font.size": 11.0,
    "axes.labelsize": 11.0,
    "axes.linewidth": 0.80,
    "xtick.labelsize": 10.0,
    "ytick.labelsize": 10.0,
    "legend.fontsize": 9.5,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "savefig.facecolor": "white",
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})


VARIANTS = [
    ("SliceBF", "Full"),
    ("SliceBF-NoMask", "w/o Masking"),
    ("SliceBF-NoBitSlice", "w/o Bit-sliced\naggregation"),
    ("SliceBF-NoPruning", "w/o Bucket\npruning"),
]
BAR_COLORS = ["#176B5B", "#C9793A", "#3F6F9C", "#7851A9"]


def load(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def number(row, key, default=0.0):
    value = row.get(key, "")
    return float(value) if value not in ("", None) else default


def style(ax):
    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_color("#555555")
        spine.set_linewidth(0.80)
    ax.set_axisbelow(True)
    ax.grid(True, which="major", axis="both", color="#B7B7B7",
            linewidth=0.45, linestyle="-", alpha=0.50)
    ax.yaxis.set_minor_locator(AutoMinorLocator(2))
    ax.grid(True, which="minor", axis="y", color="#CFCFCF",
            linewidth=0.30, linestyle=":", alpha=0.35)
    ax.tick_params(axis="both", which="major", direction="in", top=True,
                   right=True, width=0.70, length=3.0, color="#555555")
    ax.tick_params(axis="y", which="minor", direction="in", right=True,
                   width=0.45, length=1.4, color="#777777")


def plot(summary_path, output_dir):
    rows = [
        row for row in load(summary_path)
        if row["experiment"] == "E1" and row["selectivity"] == "all"
        and int(row["N"]) == 300000 and int(row["q"]) == 3
    ]
    lookup = {(row["scheme"], row["metric"]): number(row, "mean")
              for row in rows}
    ci_lookup = {(row["scheme"], row["metric"]):
                 number(row, "ci95_half") for row in rows}
    missing = [
        f"{scheme}/{metric}"
        for scheme, _ in VARIANTS
        for metric in ("total_query_ms",)
        if (scheme, metric) not in lookup
    ]
    if missing:
        raise SystemExit("Missing summary entries: " + ", ".join(missing))

    schemes = [scheme for scheme, _ in VARIANTS]
    labels = [label for _, label in VARIANTS]
    x = np.arange(len(schemes))
    total = np.array([lookup[(scheme, "total_query_ms")]
                      for scheme in schemes])
    total_ci = np.nan_to_num(np.array([
        ci_lookup.get((scheme, "total_query_ms"), 0.0)
        for scheme in schemes
    ]), nan=0.0, posinf=0.0, neginf=0.0)

    fig, ax = plt.subplots(figsize=(5.5, 3.75))
    width = 0.62
    ax.bar(
        x, total, width=width, color=BAR_COLORS,
        edgecolor="#555555", linewidth=0.45, zorder=3,
    )
    ax.errorbar(
        x, total, yerr=total_ci, fmt="none", ecolor="#404040",
        elinewidth=0.60, capsize=2.1, capthick=0.60, zorder=5,
    )

    top = float(np.max(total + total_ci))
    label_gap = max(0.012 * top, 0.03)
    relative = (total / total[0] - 1.0) * 100.0
    for index, (xpos, value, error, change) in enumerate(
            zip(x, total, total_ci, relative)):
        change_text = "reference" if index == 0 else f"{change:+.1f}%"
        ax.text(
            xpos, value + error + label_gap,
            f"{value:.2f}\n({change_text})",
            ha="center", va="bottom", fontsize=9.5, linespacing=1.05,
            clip_on=True,
        )

    # A fine reference rule makes the small masking and pruning costs visible
    # without truncating the zero-based latency axis.
    ax.axhline(total[0], color="#6F6F6F", linewidth=0.50,
               linestyle=(0, (2.0, 2.0)), alpha=0.70, zorder=2)

    ax.set_xticks(x, labels)
    ax.set_xlabel(r"SliceBF configuration ($N=300{,}000,\ q=3$)")
    ax.set_ylabel("Query time (ms)", fontweight="bold")
    # Reserve display-space headroom for the two-line labels.  The previous
    # data-proportional padding was too small after one-column scaling, so the
    # tallest label could cross the top spine in the manuscript.
    headroom = max(0.18 * top, 1.8)
    ax.set_ylim(0, math.ceil((top + headroom) * 2) / 2)
    style(ax)
    fig.tight_layout(pad=0.60)
    output_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_dir / "fig_ablation.pdf", bbox_inches="tight")
    fig.savefig(output_dir / "fig_ablation.png", dpi=600,
                bbox_inches="tight")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results")
    parser.add_argument("out")
    args = parser.parse_args()
    results = Path(args.results)
    output = Path(args.out)
    plot(results / "E1" / "summary.csv", output)
    print(f"[plot] {output / 'fig_ablation.pdf'}")


if __name__ == "__main__":
    main()
