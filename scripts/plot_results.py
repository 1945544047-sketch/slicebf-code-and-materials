#!/usr/bin/env python3
"""Render publication figures from fair-v2 summaries only."""
import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import AutoMinorLocator


# Match the visual language used in Liang et al.'s PBKS/PBKS+ evaluation
# figures: serif type, fine solid curves, compact filled markers, boxed axes,
# inward ticks on all four sides, pale two-directional grid lines, and framed
# white legends.  The main query figure mirrors PBKS's uncluttered line-chart
# presentation; statistical uncertainty remains available in the CSV tables.
plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "mathtext.fontset": "stix",
    # Figures are placed at one-column width in the manuscript.  These source
    # sizes keep all labels readable after the roughly 0.5x LaTeX scaling.
    "font.size": 11.5,
    "axes.labelsize": 11.5,
    "axes.linewidth": 0.80,
    "xtick.labelsize": 10.5,
    "ytick.labelsize": 10.5,
    "legend.fontsize": 10.0,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "savefig.facecolor": "white",
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})


SCHEME_ORDER = [
    "SliceBF", "XEBFF-Conj", "Doris", "Ren"
]
COLORS = {"SliceBF": "#1B7F6B", "XEBFF-Conj": "#8A2BE2",
          "Doris": "#FF8C33", "Ren": "#FF5A5F"}
MARKERS = {"SliceBF": "o", "XEBFF-Conj": "s", "Doris": "^", "Ren": "D"}

# Query-only styling follows the PBKS/PBKS+ evaluation figures: fine solid
# curves, compact markers, and a restrained palette on a white background.
# The hollow square and filled triangle distinguish the two close baselines
# without shifting, smoothing, or otherwise altering their observations.
QUERY_LINEWIDTHS = {
    "SliceBF": 1.10, "XEBFF-Conj": 1.10, "Doris": 1.10, "Ren": 1.10
}
QUERY_MARKERSIZES = {
    "SliceBF": 4.8, "XEBFF-Conj": 4.6, "Doris": 4.7, "Ren": 4.8
}
QUERY_COLORS = {
    # Restrained publication palette inspired by PBKS/PBKS+: emerald,
    # muted violet, warm copper, and steel blue.
    "SliceBF": "#176B5B",
    "XEBFF-Conj": "#7851A9",
    "Doris": "#C9793A",
    "Ren": "#3F6F9C",
}
QUERY_MARKERS = {
    "SliceBF": "o", "XEBFF-Conj": "s", "Doris": "D", "Ren": "^"
}
QUERY_ZORDERS = {
    "SliceBF": 6, "XEBFF-Conj": 4, "Doris": 5, "Ren": 3
}


def query_series_style(scheme):
    return {
        "linestyle": "-",
        "linewidth": QUERY_LINEWIDTHS[scheme],
        "markersize": QUERY_MARKERSIZES[scheme],
        "fillstyle": "left",
        "markerfacecolor": QUERY_COLORS[scheme],
        "markerfacecoloralt": "white",
        "markeredgecolor": QUERY_COLORS[scheme],
        "markeredgewidth": 0.80,
        "zorder": QUERY_ZORDERS[scheme],
    }


def available_schemes(*row_groups):
    present = {row["scheme"] for rows in row_groups for row in rows}
    return [scheme for scheme in SCHEME_ORDER if scheme in present]


def load(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def number(row, key, default=0.0):
    value = row.get(key, "")
    return float(value) if value not in ("", None) else default


def style(ax, *, minor_grid=False):
    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_color("#555555")
        spine.set_linewidth(0.80)
    ax.set_axisbelow(True)
    ax.grid(True, which="major", axis="both", color="#B7B7B7",
            linewidth=0.45, linestyle="-", alpha=0.50)
    ax.tick_params(axis="both", which="major", direction="in", top=True,
                   right=True, width=0.70, length=3.0, color="#555555")
    if minor_grid:
        if ax.get_xscale() == "linear":
            ax.xaxis.set_minor_locator(AutoMinorLocator(2))
        if ax.get_yscale() == "linear":
            ax.yaxis.set_minor_locator(AutoMinorLocator(2))
        ax.grid(True, which="minor", axis="both", color="#CFCFCF",
                linewidth=0.30, linestyle=":", alpha=0.35)
        ax.tick_params(axis="both", which="minor", direction="in", top=True,
                       right=True, width=0.45, length=1.4, color="#777777")


def log_y(ax):
    """Keep wide multi-scheme ranges legible without altering observations."""
    ax.set_yscale("log")
    ax.grid(True, which="minor", axis="y", color="#CFCFCF",
            linewidth=0.30, linestyle=":", alpha=0.35)


def paper_legend(ax, **kwargs):
    legend = ax.legend(frameon=True, fancybox=False, framealpha=1.0,
                       facecolor="white", edgecolor="#999999",
                       borderpad=0.20, handlelength=1.35,
                       handletextpad=0.30, labelspacing=0.12,
                       borderaxespad=0.55, **kwargs)
    legend.get_frame().set_linewidth(0.45)
    return legend


def paper_figure_legend(fig, handles, labels, **kwargs):
    legend = fig.legend(handles, labels, frameon=True, fancybox=False,
                        framealpha=1.0, facecolor="white",
                        edgecolor="#777777", borderpad=0.25,
                        handlelength=1.7, handletextpad=0.35,
                        labelspacing=0.2, **kwargs)
    legend.get_frame().set_linewidth(0.5)
    return legend


def panel_label(ax, text):
    ax.text(0.5, -0.31, text, transform=ax.transAxes, ha="center", va="top",
            fontsize=11.0, fontweight="bold", clip_on=False)


def save(fig, out, stem, *, pad=0.55, w_pad=1.15, h_pad=0.7,
         rect=None, tight=True):
    if tight:
        fig.tight_layout(pad=pad, w_pad=w_pad, h_pad=h_pad, rect=rect)
    fig.savefig(out / f"{stem}.pdf", bbox_inches="tight")
    fig.savefig(out / f"{stem}.png", dpi=600, bbox_inches="tight")
    plt.close(fig)


def plot_query(results, out):
    e1 = load(results / "E1" / "summary.csv")
    e2 = load(results / "E2" / "summary.csv")
    e1 = [r for r in e1 if r["metric"] == "total_query_ms" and
          r["selectivity"] == "all"]
    e2 = [r for r in e2 if r["metric"] == "total_query_ms" and
          r["selectivity"] == "all"]
    schemes = available_schemes(e1, e2)
    fig, axes = plt.subplots(1, 2, figsize=(6.4, 3.7))
    for scheme in schemes:
        rows = sorted((r for r in e1 if r["scheme"] == scheme),
                      key=lambda r: int(r["N"]))
        x = np.array([int(r["N"]) / 1000 for r in rows])
        y = np.array([number(r, "mean") for r in rows])
        axes[0].plot(
            x, y, color=QUERY_COLORS[scheme], marker=QUERY_MARKERS[scheme],
            **query_series_style(scheme), label=scheme)
        rows = sorted((r for r in e2 if r["scheme"] == scheme),
                      key=lambda r: int(r["q"]))
        x = np.array([int(r["q"]) for r in rows])
        y = np.array([number(r, "mean") for r in rows])
        axes[1].plot(
            x, y, color=QUERY_COLORS[scheme], marker=QUERY_MARKERS[scheme],
            **query_series_style(scheme), label=scheme)
    axes[0].set_xlabel(r"Number of documents ($\times 10^3$)")
    axes[0].set_ylabel("Query time (ms)", fontweight="bold")
    axes[0].set_xticks(sorted({int(r["N"]) // 1000 for r in e1}))
    axes[1].set_xlabel("Number of query keywords")
    axes[1].set_ylabel("Query time (ms)", fontweight="bold")
    axes[1].set_xticks([2, 3, 4, 5])
    axes[0].set_ylim(0, 50)
    axes[0].set_yticks([0, 10, 20, 30, 40, 50])
    axes[1].set_ylim(0, 60)
    axes[1].set_yticks([0, 10, 20, 30, 40, 50, 60])
    for ax in axes:
        style(ax, minor_grid=True)
    paper_legend(axes[0], loc="upper left", ncol=1, fontsize=9.5)
    paper_legend(axes[1], loc="upper right", ncol=1, fontsize=9.5)
    axes[0].text(0.5, -0.29, "(a) Query time", transform=axes[0].transAxes,
                 ha="center", va="top", fontsize=11.0, fontweight="bold",
                 clip_on=False)
    axes[0].text(0.5, -0.40, r"$(q=3)$", transform=axes[0].transAxes,
                 ha="center", va="top", fontsize=10.0, clip_on=False)
    axes[1].text(0.5, -0.29, "(b) Query time", transform=axes[1].transAxes,
                 ha="center", va="top", fontsize=11.0, fontweight="bold",
                 clip_on=False)
    axes[1].text(0.5, -0.40, r"$(N=300{,}000)$",
                 transform=axes[1].transAxes, ha="center", va="top",
                 fontsize=10.0, clip_on=False)
    save(fig, out, "fig_query", rect=(0.0, 0.0, 1.0, 1.0))


def plot_setup_storage(results, out):
    e3 = [r for r in load(results / "E3" / "summary.csv")
          if r["metric"] == "setup_ms"]
    e4 = load(results / "E4" / "raw.csv")
    schemes = [scheme for scheme in available_schemes(e3, e4)
               if any(row["scheme"] == scheme for row in e3)
               and any(row["scheme"] == scheme for row in e4)]
    fig, axes = plt.subplots(1, 2, figsize=(6.4, 3.7))
    for scheme in schemes:
        rows = sorted((r for r in e3 if r["scheme"] == scheme),
                      key=lambda r: int(r["N"]))
        x = np.array([int(r["N"]) / 1000 for r in rows])
        y = np.array([number(r, "mean") / 1000 for r in rows])
        axes[0].plot(
            x, y, color=QUERY_COLORS[scheme], marker=QUERY_MARKERS[scheme],
            **query_series_style(scheme), label=scheme)
    axes[0].set_xlabel(r"Number of documents ($\times 10^3$)")
    axes[0].set_ylabel("Setup time (s)", fontweight="bold")
    scales_k = sorted({int(r["N"]) // 1000 for r in e3})
    axes[0].set_xticks(scales_k)
    log_y(axes[0])
    style(axes[0], minor_grid=True)

    for scheme in schemes:
        rows = sorted((r for r in e4 if r["scheme"] == scheme),
                      key=lambda r: int(r["N"]))
        x = np.array([int(r["N"]) / 1000 for r in rows])
        y = np.array([number(r, "total_managed_bytes") / 2**20 for r in rows])
        axes[1].plot(
            x, y, color=QUERY_COLORS[scheme], marker=QUERY_MARKERS[scheme],
            **query_series_style(scheme), label=scheme)
    axes[1].set_xlabel(r"Number of documents ($\times 10^3$)")
    axes[1].set_xticks(scales_k)
    axes[1].set_ylabel("Managed storage (MiB)", fontweight="bold")
    style(axes[1], minor_grid=True)
    paper_legend(axes[0], loc="upper left", ncol=1, fontsize=9.5)
    paper_legend(axes[1], loc="upper left", ncol=1, fontsize=9.5)
    panel_label(axes[0], "(a) Setup time")
    panel_label(axes[1], "(b) Managed storage")
    save(fig, out, "fig_setup_storage", rect=(0.0, 0.0, 1.0, 1.0))


def plot_dynamic(results, out):
    e8_path = results / "E8" / "summary.csv"
    if e8_path.exists():
        rows = load(e8_path)
        # Only the two genuinely dynamic schemes belong in the update figure.
        # Doris and XEBFF-Conj are static baselines and therefore do not have
        # semantically comparable insertion/deletion measurements.
        schemes = [s for s in ("SliceBF", "Ren")
                   if any(row["scheme"] == s for row in rows)]
        panels = [
            ("insert", "Insertion time (ms)", "(a) Insertion"),
            ("delete", "Deletion time (ms)", "(b) Deletion"),
        ]
        fig, axes = plt.subplots(1, 2, figsize=(6.4, 3.7))
        scales = sorted({int(row["N"]) // 1000 for row in rows})
        for ax, (operation, ylabel, label) in zip(axes, panels):
            for scheme in schemes:
                selected = sorted((row for row in rows
                                   if row["scheme"] == scheme
                                   and row["selectivity"] == operation
                                   and row["metric"] == "batch_update_ms"),
                                  key=lambda row: int(row["N"]))
                if not selected:
                    continue
                x = np.array([int(row["N"]) / 1000
                              for row in selected])
                y = np.array([number(row, "mean") for row in selected])
                ax.plot(
                    x, y, color=QUERY_COLORS[scheme],
                    marker=QUERY_MARKERS[scheme],
                    **query_series_style(scheme), label=scheme,
                )
            ax.set_xlabel(r"Number of documents ($\times 10^3$)")
            ax.set_ylabel(ylabel, fontweight="bold")
            ax.set_xticks(scales)
            if operation == "delete":
                # Keep the zero baseline while adding headroom above the
                # SliceBF curve so both update series sit more centrally.
                ax.set_ylim(0.0, 0.40)
                ax.set_yticks(np.arange(0.0, 0.401, 0.05))
            else:
                ax.set_ylim(bottom=0)
            style(ax, minor_grid=True)
            paper_legend(ax, loc="upper left", ncol=1, fontsize=9.8)
            panel_label(ax, label)
        save(fig, out, "fig_dynamic", rect=(0.0, 0.0, 1.0, 1.0))
        return

    rows = load(results / "E7" / "summary.csv")
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.8))
    for ax, metric, title in [
        (axes[0], "insert_ms", "Insertion"),
        (axes[1], "delete_ms", "Deletion"),
    ]:
        selected = sorted((r for r in rows if r["metric"] == metric),
                          key=lambda r: int(r["N"]))
        x = np.array([int(r["N"]) / 1000 for r in selected])
        median = np.array([number(r, "median") for r in selected])
        p95 = np.array([number(r, "p95") for r in selected])
        ax.plot(x, median, color=COLORS["SliceBF"], marker="o", linewidth=0.9,
                markersize=3.4, markerfacecolor=COLORS["SliceBF"],
                markeredgecolor="white", markeredgewidth=0.35, label="Median")
        ax.plot(x, p95, color=COLORS["SliceBF"], marker="s",
                linewidth=0.8, linestyle="--", markersize=3.1,
                markerfacecolor="white", markeredgewidth=0.55, label="P95")
        ax.set_xlabel("Number of documents, N (K)")
        ax.set_ylabel(f"{title} time (ms)")
        ax.set_xticks(sorted({int(r["N"]) // 1000 for r in selected}))
        style(ax)
    paper_legend(axes[0], loc="best")
    panel_label(axes[0], "(a) Insertion time")
    panel_label(axes[1], "(b) Deletion time")
    save(fig, out, "fig_dynamic")


def plot_communication(results, out):
    path = results / "E6" / "summary.csv"
    if not path.exists():
        return
    rows = [row for row in load(path) if row["selectivity"] == "all"]
    schemes = available_schemes(rows)
    panels = [
        ("client_to_server_bytes", "Client-to-server communication",
         "(a) Query upload"),
        ("server_to_client_bytes", "Server-to-client communication",
         "(b) Search response"),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.4))
    for ax, (metric, ylabel, label) in zip(axes, panels):
        for scheme in schemes:
            selected = sorted((row for row in rows
                               if row["scheme"] == scheme
                               and row["metric"] == metric),
                              key=lambda row: int(row["q"]))
            if not selected:
                continue
            x = np.array([int(row["q"]) for row in selected])
            y = np.array([number(row, "mean") / 1024
                          for row in selected])
            ax.plot(
                x, y, color=QUERY_COLORS[scheme],
                marker=QUERY_MARKERS[scheme],
                **query_series_style(scheme), label=scheme,
            )
        ax.set_xlabel("Number of query keywords")
        short_label = "Upload" if metric == "client_to_server_bytes" else "Response"
        ax.set_ylabel(f"{short_label}(KiB)", fontweight="bold")
        ax.set_xticks([2, 3, 4, 5])
        log_y(ax)
        style(ax, minor_grid=True)
        panel_label(ax, label)
    paper_legend(axes[0], loc="center right", ncol=1, fontsize=6.7)
    paper_legend(axes[1], loc="center right", ncol=1, fontsize=6.7)
    save(fig, out, "fig_communication", rect=(0.0, 0.0, 1.0, 1.0))


def plot_breakdown(results, out):
    rows = [r for r in load(results / "E5" / "summary.csv")
            if r["selectivity"] == "all"]
    schemes = available_schemes(rows)
    lookup = {(r["scheme"], r["metric"]): number(r, "mean") for r in rows}
    ci_lookup = {(r["scheme"], r["metric"]): number(r, "ci95_half")
                 for r in rows}
    x = np.arange(len(schemes))
    trapdoor = np.array([lookup.get((s, "trapdoor_ms"), 0) for s in schemes])
    server = np.array([lookup.get((s, "server_ms"), 0) for s in schemes])
    client = np.array([lookup.get((s, "client_ms"), 0) for s in schemes])
    total = np.array([lookup.get((s, "total_query_ms"), 0) for s in schemes])
    total_ci = np.array([
        ci_lookup.get((s, "total_query_ms"), 0) for s in schemes
    ])
    total_ci = np.nan_to_num(total_ci, nan=0.0, posinf=0.0, neginf=0.0)

    fig, ax = plt.subplots(figsize=(5.6, 3.4))
    width = 0.62
    bar_kw = dict(width=width, edgecolor="white", linewidth=0.45, zorder=3)
    ax.bar(x, trapdoor, color="#C9793A", label="Trapdoor", **bar_kw)
    ax.bar(x, server, bottom=trapdoor, color="#3F6F9C",
           label="Server", **bar_kw)
    ax.bar(x, client, bottom=trapdoor + server, color="#176B5B",
           label="Client", **bar_kw)
    ax.errorbar(
        x, total, yerr=total_ci, fmt="none", ecolor="#444444",
        elinewidth=0.60, capsize=2.1, capthick=0.60, zorder=5,
    )
    for xpos, value, error in zip(x, total, total_ci):
        ax.text(xpos, value + error + 0.45, f"{value:.1f}",
                ha="center", va="bottom", fontsize=7.0)
    ax.set_xticks(x, schemes)
    ax.set_xlabel(r"Scheme ($N=300{,}000,\ q=3$)")
    ax.set_ylabel("Query time(ms)", fontweight="bold")
    ax.set_ylim(0, 45)
    ax.set_yticks(np.arange(0, 46, 5))
    paper_legend(ax, ncol=1, loc="upper left", fontsize=7.0)
    style(ax, minor_grid=True)
    save(fig, out, "fig_breakdown", rect=(0.0, 0.0, 1.0, 1.0))


def plot_first_after_update(results, out):
    path = results / "E8" / "summary.csv"
    if not path.exists():
        return
    rows = load(path)
    schemes = available_schemes(rows)
    categories = [
        ("delete", "batch_update_ms", "Delete\nupdate"),
        ("delete", "first_query_ms", "Delete\nfirst query"),
        ("insert", "batch_update_ms", "Insert\nupdate"),
        ("insert", "first_query_ms", "Insert\nfirst query"),
    ]
    x = np.arange(len(categories))
    width = 0.8 / max(1, len(schemes))
    fig, ax = plt.subplots(figsize=(5.6, 3.0))
    for index, scheme in enumerate(schemes):
        lookup = {(row["selectivity"], row["metric"]): number(row, "mean")
                  for row in rows if row["scheme"] == scheme}
        values = [lookup.get((operation, metric), 0.0)
                  for operation, metric, _ in categories]
        offset = (index - (len(schemes) - 1) / 2) * width
        ax.bar(x + offset, values, width=width, color=COLORS[scheme],
               label=scheme)
    ax.set_xticks(x, [label for _, _, label in categories])
    ax.set_ylabel("Time (ms, log scale)")
    log_y(ax)
    ax.legend(frameon=False, fontsize=8)
    style(ax)
    save(fig, out, "fig_first_after_update")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results")
    parser.add_argument("out")
    args = parser.parse_args()
    results, out = Path(args.results), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plot_query(results, out)
    plot_setup_storage(results, out)
    plot_dynamic(results, out)
    plot_communication(results, out)
    plot_breakdown(results, out)
    plot_first_after_update(results, out)
    print(f"[plot] publication figures written to {out}")


if __name__ == "__main__":
    main()
