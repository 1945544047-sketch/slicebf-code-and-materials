"""Restore exact paper corpus prefixes from the lossless frozen snapshot."""
import argparse
import gzip
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "work/corpus")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        raise SystemExit("Output already exists; select a new output directory.")
    manifest = json.loads((ROOT / "data/original_manifest.json").read_text(encoding="utf-8"))
    scales = manifest["scale_sizes"]
    out.mkdir(parents=True)
    handles = {n: (out / f"corpus_N{n}.jsonl").open("wb") for n in scales}
    hashes = {n: hashlib.sha256() for n in scales}
    count = 0
    try:
        with gzip.open(ROOT / "data/frozen/corpus_N300000.jsonl.gz", "rb") as inp:
            for count, line in enumerate(inp, 1):
                for n in scales:
                    if count <= n:
                        handles[n].write(line)
                        hashes[n].update(line)
        if count != 300000:
            raise ValueError(f"Expected 300000 documents, got {count}")
        for n in scales:
            actual = hashes[n].hexdigest()
            expected = manifest["corpora"][f"N{n}"]["sha256"]
            if actual != expected:
                raise ValueError(f"Prefix hash mismatch at N={n}")
            print(f"N={n}: SHA-256 verified")
    finally:
        for handle in handles.values():
            handle.close()
    shutil.copytree(ROOT / "data/queries", out / "queries")
    for name, info in manifest["query_workload"]["files"].items():
        actual = hashlib.sha256((out / "queries" / name).read_bytes()).hexdigest()
        if actual != info["sha256"]:
            raise ValueError(f"Query/oracle hash mismatch: {name}")
    print(f"Restored exact corpus and queries: {out}")


if __name__ == "__main__":
    main()
