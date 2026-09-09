#!/usr/bin/env python3
"""
Freeze the 300K distinct-record NSF corpus for FINAL_300K_EXPERIMENT_CHECKLIST.

Source: data/processed_500k/corpus_N500000.jsonl (500K rows, frozen
tokenization/df-filter, but containing duplicate award ids and duplicate token
occurrences inside some documents).  We keep the first occurrence of each
award id, canonicalize every keyword set as ``sorted(set(tokens))``, take the
first 300,000 distinct documents in the existing order, and emit six strictly
nested prefixes:

    50K / 100K / 150K / 200K / 250K / 300K

The remaining distinct records (~43K) are written to a reserve file and are NOT
used for the main experiments (checklist section 3).  Tokenization is unchanged;
only duplicate rows are dropped, so this does not "inflate by duplicating".

Outputs (under --out, default data/processed_300k_v2):
    corpus_N{50000,100000,150000,200000,250000,300000}.jsonl
    reserve_pool.jsonl
    manifest.json   (per-scale SHA-256 and normalization statistics)
"""
import argparse
import hashlib
import json
from pathlib import Path


SCALES = [50000, 100000, 150000, 200000, 250000, 300000]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source",
                    default="data/processed_500k/corpus_N500000.jsonl")
    ap.add_argument("--out", default="data/processed_300k_v2")
    ap.add_argument("--main", type=int, default=300000)
    ap.add_argument("--seed", type=int, default=20260711)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Stream source, keep first occurrence of each id, and canonicalize the
    # document keyword set.  This is the *only* place where duplicates are
    # removed; the C++ loader rejects non-canonical inputs instead of silently
    # giving one scheme a different logical corpus.
    seen = set()
    main_docs = []      # first `main` distinct, canonical documents
    reserve = []        # canonical distinct documents beyond `main`
    source_rows = 0
    duplicate_id_rows = 0
    raw_token_occurrences = 0
    unique_keyword_pairs = 0
    docs_with_duplicate_tokens = 0
    with open(args.source, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            source_rows += 1
            doc = json.loads(line)
            did = str(doc["id"])
            if did in seen:
                duplicate_id_rows += 1
                continue
            seen.add(did)
            tokens = doc.get("tokens", [])
            if not isinstance(tokens, list) or not all(
                    isinstance(token, str) and token for token in tokens):
                raise SystemExit(f"invalid tokens for document {did}")
            canonical_tokens = sorted(set(tokens))
            raw_token_occurrences += len(tokens)
            unique_keyword_pairs += len(canonical_tokens)
            if len(canonical_tokens) != len(tokens):
                docs_with_duplicate_tokens += 1
            canonical = {"id": did, "tokens": canonical_tokens}
            # Compact, stable serialization keeps the very large corpus files
            # smaller and makes SHA-256 reproducible across runs.
            s = json.dumps(canonical, ensure_ascii=False,
                           sort_keys=True, separators=(",", ":"))
            if len(main_docs) < args.main:
                main_docs.append((canonical, s))
            else:
                reserve.append((canonical, s))
    removed_token_occurrences = raw_token_occurrences - unique_keyword_pairs
    print(f"[normalize] rows={source_rows} duplicate_ids={duplicate_id_rows} "
          f"distinct_ids={len(seen)} main={len(main_docs)} "
          f"reserve={len(reserve)} duplicate-token-docs="
          f"{docs_with_duplicate_tokens} removed-token-occurrences="
          f"{removed_token_occurrences}", flush=True)
    if len(main_docs) < args.main:
        raise SystemExit(f"not enough distinct docs: {len(main_docs)} < {args.main}")

    # Write nested-prefix corpora (each smaller is a strict prefix of larger).
    manifest = {
        "created_seed": args.seed,
        "normalization_version": 2,
        "normalization": "keep-first-id; sorted(set(tokens))",
        "source": args.source,
        "source_sha256": sha256_file(args.source),
        "source_rows": source_rows,
        "duplicate_id_rows_removed": duplicate_id_rows,
        "distinct_pool": len(seen),
        "main_size": args.main,
        "reserve_size": len(reserve),
        "raw_token_occurrences_after_id_dedup": raw_token_occurrences,
        "unique_keyword_pairs_after_token_dedup": unique_keyword_pairs,
        "duplicate_token_occurrences_removed": removed_token_occurrences,
        "documents_with_duplicate_tokens": docs_with_duplicate_tokens,
        "scale_sizes": SCALES,
        "corpora": {},
    }
    for n in SCALES:
        path = out / f"corpus_N{n}.jsonl"
        with open(path, "w", encoding="utf-8") as w:
            for _doc, s in main_docs[:n]:
                w.write(s + "\n")
        # stats
        vocab = set()
        pairs = 0
        for doc, _s in main_docs[:n]:
            toks = doc["tokens"]
            pairs += len(toks)
            vocab.update(toks)
        manifest["corpora"][f"N{n}"] = {
            "file": str(path).replace("/", "\\"),
            "sha256": sha256_file(path),
            "n_docs": n,
            "vocab_size": len(vocab),
            "unique_keyword_pairs": pairs,
            "avg_unique_terms_per_doc": round(pairs / n, 4),
            "tokens_sorted_unique": True,
        }
        print(f"[write] N={n}: vocab={len(vocab)} pairs={pairs} "
              f"avg={pairs/n:.2f}", flush=True)

    # Reserve pool (not used in main experiments).
    rpath = out / "reserve_pool.jsonl"
    with open(rpath, "w", encoding="utf-8") as w:
        for _doc, s in reserve:
            w.write(s + "\n")
    manifest["reserve_file"] = str(rpath).replace("/", "\\")
    manifest["reserve_sha256"] = sha256_file(rpath)

    with open(out / "manifest.json", "w", encoding="utf-8") as w:
        json.dump(manifest, w, ensure_ascii=False, indent=2)
    print(f"[done] manifest -> {out/'manifest.json'}", flush=True)


if __name__ == "__main__":
    main()
