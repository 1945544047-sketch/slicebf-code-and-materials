#!/usr/bin/env python3
"""
Generate a deterministic frozen query workload and plaintext oracle for a
nested corpus whose minimum and maximum scales are supplied on the command
line.  The fair-v2 experiment uses 50K and 300K, respectively.

  * q = 2, 3, 4, 5, each with >= 80 fixed queries
  * three result-size buckets rare / medium / common per q
  * every query has a NON-EMPTY result on the smallest (50K) prefix, so it stays
    valid for all larger nested scales (Search-vs-N uses q=3 queries unchanged)
  * empty-intersection queries do not dominate the workload
  * emits q{2..5}_80.jsonl (same schema as the old data/processed/queries) plus
    oracle_results.json with result_ids computed on the configured maximum

Determinism: fixed seed; term selection and combination are seeded.  Buckets are
defined by the document frequency (df) of the query terms on the 50K prefix:
rare / medium / common term bands, matching the original rare/medium/common
naming.  Output schema is byte-compatible with the C++ runner (reads `terms`)
and load_oracle (reads `q2..q5` -> {query_id,bucket,q,terms,result_size,result_ids}).
"""
import argparse
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_tokens(path, limit=None):
    """Return list of (doc_id, set_of_tokens)."""
    docs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            docs.append((d["id"], set(d["tokens"])))
            if limit and len(docs) >= limit:
                break
    return docs


def build_postings(docs):
    """term -> sorted list of doc indices (into docs)."""
    postings = defaultdict(list)
    for i, (_id, toks) in enumerate(docs):
        for t in toks:
            postings[t].append(i)
    return postings


def intersect(postings, terms):
    """Sorted list of doc indices where all terms co-occur."""
    lists = [postings.get(t, []) for t in terms]
    if any(len(l) == 0 for l in lists):
        return []
    lists.sort(key=len)
    cur = set(lists[0])
    for l in lists[1:]:
        cur &= set(l)
        if not cur:
            return []
    return sorted(cur)


def gen_candidates(q, docs_50k, postings_50k, rng, n_candidates):
    """Document-anchored generation: pick a doc that has >= q distinct tokens,
    sample q of its tokens as the conjunction.  This guarantees a NON-EMPTY
    result on the 50K prefix (the anchor doc always matches), so the query is
    valid for every larger nested scale.  Returns dict terms_tuple -> size_50k.
    """
    eligible = [i for i, (_id, toks) in enumerate(docs_50k) if len(toks) >= q]
    if not eligible:
        return {}
    cand = {}
    tries = 0
    max_tries = n_candidates * 40
    while len(cand) < n_candidates and tries < max_tries:
        tries += 1
        di = rng.choice(eligible)
        # Sorting before seeded sampling removes dependence on Python's hash
        # randomization.  The same corpus and seed now produce byte-identical
        # query files on every machine.
        toks = sorted(docs_50k[di][1])
        terms = tuple(sorted(rng.sample(toks, q)))
        if terms in cand:
            continue
        size = len(intersect(postings_50k, list(terms)))
        if size >= 1:
            cand[terms] = size
    return cand


def split_buckets(cand, per_q):
    """Split candidate queries into rare/medium/common by 50K result_size.

    rare  = smallest results, common = largest results, medium = middle.
    Returns list of (terms, size, bucket) with up to per_q total, balanced.
    """
    items = sorted(cand.items(), key=lambda kv: (kv[1], kv[0]))
    thirds = [per_q // 3, per_q // 3, per_q - 2 * (per_q // 3)]
    targets = dict(zip(["rare", "medium", "common"], thirds))
    n = len(items)
    rare_pool = items[: n // 3]
    medium_pool = items[n // 3 : 2 * n // 3]
    common_pool = items[2 * n // 3 :]
    out = []
    for bucket, pool in [("rare", rare_pool), ("medium", medium_pool),
                         ("common", common_pool)]:
        take = pool[: targets[bucket]] if bucket != "common" \
            else pool[-targets[bucket]:]
        for terms, size in take:
            out.append((list(terms), size, bucket))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default="data/processed_300k_v2")
    ap.add_argument("--out-dir", default="data/processed_300k_v2/queries")
    ap.add_argument("--seed", type=int, default=20260711)
    ap.add_argument("--per-q", type=int, default=80)
    ap.add_argument("--min-scale", type=int, default=50000)
    ap.add_argument("--max-scale", type=int, default=300000)
    ap.add_argument("--arities", default="2,3,4,5")
    args = ap.parse_args()

    corpus_dir = Path(args.corpus_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    arities = [int(x) for x in args.arities.split(",") if x]

    print(f"[load] 50K prefix from corpus_N{args.min_scale}.jsonl", flush=True)
    docs_50k = load_tokens(corpus_dir / f"corpus_N{args.min_scale}.jsonl")
    postings_50k = build_postings(docs_50k)
    print(f"[load] 50K prefix: {len(docs_50k)} docs, {len(postings_50k)} terms",
          flush=True)

    all_queries = {}  # q -> list of query dicts
    for q in arities:
        rng = random.Random(args.seed + q * 1000003)
        # over-generate candidates so bucketed thirds each fill to per_q/3
        cand = gen_candidates(q, docs_50k, postings_50k, rng,
                              n_candidates=args.per_q * 8)
        picked = split_buckets(cand, args.per_q)
        qlist = []
        idx = {"rare": 0, "medium": 0, "common": 0}
        for terms, size, bucket in picked:
            qid = f"{bucket}_{idx[bucket]:03d}"
            idx[bucket] += 1
            qlist.append({
                "query_id": qid, "terms": terms, "q": q,
                "result_size": size, "bucket": bucket,
            })
        if len(qlist) < args.per_q:
            print(f"[warn] q={q}: only {len(qlist)}/{args.per_q} queries",
                  flush=True)
        all_queries[q] = qlist
        # write q{n}_80.jsonl
        qpath = out_dir / f"q{q}_{args.per_q}.jsonl"
        with open(qpath, "w", encoding="utf-8") as f:
            for e in qlist:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"[write] {qpath} : {len(qlist)} queries", flush=True)

    # oracle on FULL max-scale corpus
    print(f"[oracle] loading full N{args.max_scale} corpus for oracle...",
          flush=True)
    docs_full = load_tokens(corpus_dir / f"corpus_N{args.max_scale}.jsonl")
    needed = set()
    for q in arities:
        for e in all_queries[q]:
            needed.update(e["terms"])
    print(f"[oracle] building postings for {len(needed)} query terms over "
          f"{len(docs_full)} docs...", flush=True)
    post_full = defaultdict(list)
    for i, (_id, toks) in enumerate(docs_full):
        for t in toks:
            if t in needed:
                post_full[t].append(i)

    def intersect_full(terms):
        lists = [post_full.get(t, []) for t in terms]
        if any(len(l) == 0 for l in lists):
            return []
        lists.sort(key=len)
        cur = set(lists[0])
        for l in lists[1:]:
            cur &= set(l)
            if not cur:
                return []
        return sorted(cur)

    oracle = {}
    for q in arities:
        entries = []
        for e in all_queries[q]:
            hits = intersect_full(e["terms"])
            ids = [docs_full[i][0] for i in hits]
            entries.append({
                "query_id": e["query_id"], "q": q, "bucket": e["bucket"],
                "terms": e["terms"], "result_size": len(ids),
                "result_ids": ids,
            })
        oracle[f"q{q}"] = entries
    opath = out_dir / "oracle_results.json"
    with open(opath, "w", encoding="utf-8") as f:
        json.dump(oracle, f, ensure_ascii=False, sort_keys=True,
                  separators=(",", ":"))
    print(f"[write] {opath}", flush=True)

    # Bind the workload and oracle to the normalized corpus manifest.  The
    # formal runner records this manifest hash, so stale query files cannot be
    # combined accidentally with a new corpus.
    manifest_path = corpus_dir / "manifest.json"
    if manifest_path.exists():
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        query_files = {}
        for q in arities:
            qpath = out_dir / f"q{q}_{args.per_q}.jsonl"
            query_files[qpath.name] = {
                "sha256": sha256_file(qpath),
                "queries": len(all_queries[q]),
            }
        query_files[opath.name] = {"sha256": sha256_file(opath)}
        manifest["query_workload"] = {
            "generator_seed": args.seed,
            "minimum_scale": args.min_scale,
            "oracle_scale": args.max_scale,
            "arities": arities,
            "queries_per_arity": args.per_q,
            "generation": "document-anchored; sorted tokens; fixed seed",
            "files": query_files,
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2,
                      sort_keys=True)
        print(f"[bind] workload hashes -> {manifest_path}", flush=True)
    print("[done] query + oracle generation complete", flush=True)


if __name__ == "__main__":
    main()
