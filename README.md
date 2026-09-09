# SliceBF

Code and experimental materials for the paper **“SliceBF: Leakage-Reduced
Dynamic Conjunctive Searchable Encryption with Bit-Sliced Counting Bloom
Filters.”**

SliceBF is a research prototype for leakage-reduced dynamic conjunctive
searchable symmetric encryption. It keeps sparse counting Bloom filter state at
the owner and exposes protected, transposed bit slices for word-parallel query
processing at the server.

> **Research-use notice:** this prototype has not been independently audited and
> is not intended for production deployment.

## Repository contents

- `cpp/`: C++17 implementation, experiment driver, and correctness tests.
- `data/frozen/`: lossless compressed 300K-document corpus snapshot.
- `data/queries/`: fixed query workloads and plaintext oracle results.
- `results/main/`: measurement tables used for the main experimental figures.
- `results/ablation/`: SliceBF ablation measurements.
- `scripts/`: corpus restoration, experiment, verification, summary, and plotting tools.
- `reference_figures/`: reference plots generated from the archived results.
- `CHECKSUMS.sha256`: SHA-256 checksums for the distributed artifact files.

The repository does **not** redistribute implementations of the comparison
schemes. Recorded comparison measurements used by the paper are retained in
`results/main/`; `scripts/run_slicebf_experiments.py` runs SliceBF and its
ablations only.

## Requirements

- CMake 3.16 or newer
- A C++17 compiler
- OpenSSL development libraries
- Python 3
- Python packages in `requirements.txt` for figure reproduction

## Build and test

Linux or macOS:

```bash
cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Windows with a multi-configuration generator:

```powershell
cmake -S cpp -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Verify the archived artifact

The verifier checks package hashes, the frozen corpus and query workload, raw
measurement coverage, correctness flags, and finite timing/storage values:

```bash
python scripts/verify_artifact.py
```

A successful run ends with `"status": "PASS"`.

## Restore the frozen corpus

The experiment driver expects uncompressed corpus prefixes. Restore the exact
50K–300K paper inputs and fixed queries with:

```bash
python scripts/prepare_corpus.py --out work/corpus
```

The command refuses to overwrite an existing output directory and verifies all
restored hashes against `data/original_manifest.json`.

## Reproduce summaries and figures

Install the pinned plotting dependencies and regenerate the summaries and four
figures from the archived measurement tables:

```bash
python -m pip install -r requirements.txt
python scripts/reproduce_figures.py --out work/reproduced
```

This reproduces the reported numerical summaries and plots without rerunning
timing experiments. Small metadata or font differences can change image-file
hashes across platforms.

## Rerun SliceBF experiments

First restore the corpus and build `run_experiments`. A small E1 run can then be
started with:

```bash
python scripts/run_slicebf_experiments.py \
  --binary build/run_experiments \
  --corpus work/corpus \
  --out work/e1-smoke \
  --campaign E1 \
  --scales 50000 \
  --runs 1 \
  --execute
```

On Windows, use `build/Release/run_experiments.exe` for `--binary`. Remove the
reduced `--scales` and `--runs` options and select `--campaign all` to schedule
the complete SliceBF campaign. Timing results depend on hardware, compiler,
OpenSSL version, system load, and CPU-affinity support.

## Data and licensing

The frozen corpus is derived from public-domain U.S. National Science
Foundation Award Search data and contains only award identifiers and token
lists. See `DATA_NOTICE` for provenance and reuse details.

Project-created code and materials are released under the MIT License in
`LICENSE`. The bundled `cpp/third_party/json.hpp` retains its embedded
third-party copyright and license notices.

## Citation

If you use this artifact, please cite the SliceBF paper. Full bibliographic
details will be added after publication.

The frozen `v1.0.0` artifact and downloadable archive are available from the
[GitHub release](https://github.com/1945544047-sketch/slicebf-code-and-materials/releases/tag/v1.0.0).
