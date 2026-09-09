"""Run the SliceBF rows of the paper campaign in fresh pinned processes."""
import argparse
import ctypes
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


VARIANTS = ["full", "no-mask", "no-bit-slice", "no-pruning"]


def pin_cpu(cpu):
    if os.name == "nt":
        if cpu < 0 or cpu >= 64:
            raise ValueError("Windows CPU must be in 0..63")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        kernel.SetProcessAffinityMask.restype = ctypes.c_int
        if not kernel.SetProcessAffinityMask(kernel.GetCurrentProcess(), 1 << cpu):
            raise ctypes.WinError(ctypes.get_last_error())
    elif hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {cpu})
    else:
        raise RuntimeError("CPU pinning is unavailable on this platform")


def units(args):
    campaigns = ["E1", "E2", "E3", "E4", "E8", "ablation"] \
        if args.campaign == "all" else [args.campaign]
    scales = [int(n) for n in args.scales.split(",")]
    for campaign in campaigns:
        count = 1 if campaign == "E4" else args.runs
        for run in range(count):
            variants = VARIANTS if campaign == "ablation" else ["full"]
            for variant in variants:
                ns = [scales[-1]] if campaign in {"E2", "ablation"} else scales
                for n in ns:
                    qs = [2, 3, 4, 5] if campaign == "E2" else [3]
                    for q in qs:
                        exp = "E1" if campaign == "ablation" else campaign
                        unit = f"{campaign}/{variant}/N{n}_q{q}_r{run}"
                        out = args.out / "runs" / unit
                        cmd = [str(args.binary), "--exp", exp,
                               "--corpus-dir", str(args.corpus),
                               "--query-dir", str(args.corpus / "queries"),
                               "--output-dir", str(out),
                               "--scales", str(n), "--arities", str(q),
                               "--run-id", str(run), "--repetitions", "1",
                               "--warmup", "80" if campaign in {"E1", "E2", "ablation"} else "10",
                               "--seed", "20260711",
                               "--update-cycles", str(args.update_cycles),
                               "--slicebf-variant", variant]
                        yield unit, cmd


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=root / "work/corpus")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--campaign", choices=["all", "E1", "E2", "E3", "E4", "E8", "ablation"], default="all")
    parser.add_argument("--scales", default="50000,100000,150000,200000,250000,300000")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--update-cycles", type=int, default=100)
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if min(args.runs, args.update_cycles) < 1:
        parser.error("run counts and update cycles must be positive")
    sizes = [int(n) for n in args.scales.split(",")]
    if not sizes or sizes != sorted(set(sizes)) or sizes[0] < 1:
        parser.error("--scales must be positive, unique, and increasing")
    args.binary = args.binary.resolve()
    args.corpus = args.corpus.resolve()
    args.out = args.out.resolve()
    plan = list(units(args))
    print(f"planned_processes={len(plan)}")
    if not args.execute:
        return
    if not args.binary.is_file():
        parser.error(f"binary not found: {args.binary}")
    if args.out.exists():
        parser.error(f"output exists: {args.out}")
    pin_cpu(args.cpu)
    args.out.mkdir(parents=True)
    (args.out / "plan.json").write_text(json.dumps({
        "platform": platform.platform(), "python": sys.version,
        "cpu": args.cpu, "units": [{"unit": u, "command": c} for u, c in plan]
    }, indent=2) + "\n", encoding="utf-8")
    for index, (unit, command) in enumerate(plan, 1):
        print(f"[{index}/{len(plan)}] {unit}", flush=True)
        subprocess.run(command, check=True)
    print(f"campaign_complete={args.out}")


if __name__ == "__main__":
    main()
