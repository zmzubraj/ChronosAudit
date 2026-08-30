# Reproducibility report

## Inputs

- Frozen cohort: 417 case envelopes listed in `04-data/provenance-manifest.csv`.
- Input closure: every case must be `VERIFIED`, `strict_snapshot_closed=true`, and carry
  both Alchemy and Infura provider families.
- The analysis reads upstream files in place and does not modify the source repository.

## Execution

```text
python3 -m unittest -v 05-analysis/code/test_build_tables.py 05-analysis/code/test_derive_mpp_results.py 05-analysis/code/test_build_figures.py
python3 05-analysis/code/derive_mpp_results.py --cases-dir <frozen-cases-directory> --output-dir 05-analysis/results --provenance-manifest 04-data/provenance-manifest.csv
python3 05-analysis/code/build_tables.py --summary 05-analysis/results/results-summary.json --output-dir 06-visuals/tables --analysis-dir 05-analysis/results
python3 05-analysis/code/build_figures.py --summary 05-analysis/results/results-summary.json --cases 05-analysis/results/analysis_cases.csv --output-dir 06-visuals/figures
```

All analysis and SVG generation use the Python standard library. PNG derivatives are
local presentation artifacts; SVG files are the canonical vector masters. The suite
currently passes locally. Independent reproduction has not yet occurred.

## Determinism and limitations

Rows are sorted by case identifier; JSON uses sorted keys; CSV schemas are fixed; no
randomness, network call, or clock value enters a numeric result. The paper reuses upstream
deployment, incident, bytecode, and proxy fields and therefore inherits upstream measurement
error. The source-rights review remains incomplete for redistribution of row-level derivatives.
