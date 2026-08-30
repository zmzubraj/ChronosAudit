# ChronosAudit — Latest Full Organized Workspace

**Date:** 2026-08-17
**Research problem:** Pre-Incident Smart-Contract Exploit Detection

This package consolidates the manuscript, executable artifact, evidence history, and current status reports used in the ChronosAudit work. **For every new chat or continuation, open only `CONTINUE_HERE.md` first.** It is the sole human-readable current-status and continuation authority. Historical reports and recovery material remain preserved for provenance but are not active context.

## Folders

- `01_Manuscript/` — latest submission DOCX + PDF.
- `02_Executable_Artifact/` — complete runnable research artifact preserving its original relative paths. Contains source code, raw/processed/external data, configs, review files, schemas, tests, reports, Docker setup, and all execution entry points.
- `03_Research_Reports/` — stage qualification, live-execution, external-evidence, verification, and gate reports.
- `04_R0_R5_Outputs/` — strict/provisional R0–R5 certification and leave-one-mechanism-family-out outputs.
- `05_Figures/` — manuscript figures.
- `06_QA_Reproducibility/` — accessibility, coverage, checksum, rendering, regeneration, provider-probe, split, and production-qualification logs.
- `07_Provenance/` — release manifest and original release checksums/readme.
- `08_Build_Scripts/` — manuscript/figure generation and revision scripts.
- `09_Legacy_Reference/` — immediately preceding manuscript retained only for traceability.

## Run the artifact

```bash
cd 02_Executable_Artifact
python -m pip install -e .
python -m pytest -q
python verify_stage2.py
python run_split_audit.py
python production_qualification.py
```

For live evidence acquisition, use `03_Research_Reports/Stage2_Live_Execution_Runbook.md`. Provider/API credentials are intentionally excluded and must be supplied via environment variables.

## Important scientific status

The package remains fail-closed. Historical snapshot authority is **417/417** and the deployment denominator is **20,000/20,000**. A separate AI-only adjudication track completed **417/417** but failed its reliability threshold and has no effect on the independent-human counter, which remains **0/417**. Controls, qualified outcomes, R5 blocks, release eligibility, and external regeneration remain open. See `CONTINUE_HERE.md` for the canonical counters and continuation order.

Reports dated 2026-08-07 through 2026-08-09 are retained as historical execution/provenance snapshots. Where their counters differ from the 2026-08-17 reports, the later machine-verified counters are current.
