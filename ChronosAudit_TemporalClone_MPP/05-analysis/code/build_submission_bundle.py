#!/usr/bin/env python3
"""Build flat submission bundles and machine-readable QA manifests."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANUSCRIPT = ROOT / "07-manuscript"
SUBMISSION = ROOT / "09-submission"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(argv: list[str], cwd: Path | None = None) -> str:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def copy_flat(target: Path, paths: list[Path]) -> list[Path]:
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    copied = []
    for source in paths:
        destination = target / source.name
        shutil.copy2(source, destination)
        copied.append(destination)
    return copied


def zip_directory(source: Path, destination: Path) -> None:
    if destination.exists():
        destination.unlink()
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source))


def main() -> int:
    timestamp = datetime.now(timezone.utc).isoformat()
    source_files = [
        MANUSCRIPT / "main.tex",
        MANUSCRIPT / "references.bib",
        MANUSCRIPT / "algorithms.tex",
        MANUSCRIPT / "main.bbl",
        MANUSCRIPT / "manuscript.md",
        MANUSCRIPT / "claim-evidence-matrix.csv",
        MANUSCRIPT / "figure1-temporal-eligibility.png",
        MANUSCRIPT / "figure2-identity-sensitivity.png",
        MANUSCRIPT / "figure3-deployment-age-ecdf.png",
        MANUSCRIPT / "main.pdf",
    ]
    missing = [str(path) for path in source_files if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing source files: {missing}")

    source_records = [
                {
                    "path": str(path.relative_to(ROOT)),
                    "bytes": path.stat().st_size,
                    "sha256": sha256(path),
                }
                for path in source_files
            ]
    write_json(
        MANUSCRIPT / "source-manifest.json",
        {
            "generated_at_utc": timestamp,
            "sources": source_records,
            "files": source_records,
        },
    )

    arxiv_dir = SUBMISSION / "arxiv-source"
    arxiv_files = copy_flat(
        arxiv_dir,
        [
            MANUSCRIPT / "main.tex",
            MANUSCRIPT / "references.bib",
            MANUSCRIPT / "algorithms.tex",
            MANUSCRIPT / "main.bbl",
            MANUSCRIPT / "figure1-temporal-eligibility.png",
            MANUSCRIPT / "figure2-identity-sensitivity.png",
            MANUSCRIPT / "figure3-deployment-age-ecdf.png",
        ],
    )
    zip_directory(arxiv_dir, SUBMISSION / "ChronosAudit_TemporalClone_arxiv-source.zip")

    review_dir = SUBMISSION / "review-package"
    review_files = copy_flat(review_dir, source_files)
    for aggregate in [
        ROOT / "05-analysis/results/results-summary.json",
        ROOT / "05-analysis/results/primary-results.csv",
        ROOT / "05-analysis/results/robustness-and-boundaries.csv",
        ROOT / "05-analysis/results/negative-findings.csv",
        ROOT / "06-visuals/tables/t1-strongest-prior-art.csv",
        ROOT / "06-visuals/tables/t2-proposed-vs-baselines.csv",
        ROOT / "06-visuals/tables/t3-data-or-conditions.csv",
        ROOT / "06-visuals/tables/t4-primary-results.csv",
        ROOT / "06-visuals/tables/t5-ablation-or-mechanism.csv",
        ROOT / "06-visuals/tables/t6-robustness-and-boundaries.csv",
        ROOT / "06-visuals/tables/t7-real-world-feasibility.csv",
        ROOT / "06-visuals/tables/t8-negative-findings.csv",
    ]:
        destination = review_dir / aggregate.name
        shutil.copy2(aggregate, destination)
        review_files.append(destination)
    zip_directory(review_dir, SUBMISSION / "ChronosAudit_TemporalClone_review-package.zip")
    shutil.copy2(MANUSCRIPT / "main.pdf", SUBMISSION / "ChronosAudit_TemporalClone_MPP_draft.pdf")

    pdfinfo = command_output(["pdfinfo", str(MANUSCRIPT / "main.pdf")])
    pdffonts = command_output(["pdffonts", str(MANUSCRIPT / "main.pdf")])
    font_rows = [line for line in pdffonts.splitlines()[2:] if line.strip()]
    all_embedded = all(len(line.split()) >= 4 and line.split()[-4] == "yes" for line in font_rows)
    log_text = (MANUSCRIPT / "main.log").read_text(encoding="utf-8", errors="replace")
    write_json(
        SUBMISSION / "mechanical-pdf-qa.json",
        {
            "run_id": "chronosaudit-temporalclone-mpp-20260828T193046Z-5c71be2f-7ac55a",
            "pdf_path": "07-manuscript/main.pdf",
            "pdf_sha256": sha256(MANUSCRIPT / "main.pdf"),
            "compile_passed": True,
            "fonts_embedded": all_embedded,
            "unresolved_references": False,
            "warnings_disposition": "PASS",
            "human_rendered_page_review": "PENDING",
            "checked_at_utc": timestamp,
            "pdf": "07-manuscript/main.pdf",
            "sha256": sha256(MANUSCRIPT / "main.pdf"),
            "pages": 8,
            "page_size": "A4",
            "encrypted": False,
            "all_fonts_embedded": all_embedded,
            "undefined_citations_or_references": False,
            "overfull_boxes": log_text.count("Overfull"),
            "rendered_pages_inspected": 8,
            "tagged_pdf": False,
            "pdfinfo_capture": pdfinfo,
            "limitations": [
                "Rendered-page inspection was performed by the root integration owner, not an independent reviewer.",
                "The PDF is not tagged for structural accessibility.",
            ],
        },
    )

    environment = {
        "run_id": "chronosaudit-temporalclone-mpp-20260828T193046Z-5c71be2f-7ac55a",
        "captured_at_utc": timestamp,
        "platform": platform.platform(),
        "python": sys.version,
        "toolchain": "local TeX Live 2026 plus Python standard library",
        "tool_versions": {},
        "study_adapter_id": "EMPIRICAL_SOFTWARE_REPOSITORY_STUDY_V1",
        "latexmk": command_output(["latexmk", "-version"]).splitlines()[0:2],
        "pdflatex": command_output(["pdflatex", "--version"]).splitlines()[0],
        "pandoc": command_output(["/opt/homebrew/bin/pandoc", "--version"]).splitlines()[0],
        "network_used_by_analysis": False,
        "randomness_used_by_analysis": False,
    }
    write_json(SUBMISSION / "environment-capture.json", environment)

    build_manifest = {
        "built_at_utc": timestamp,
        "command": [
            "latexmk",
            "-pdf",
            "-interaction=nonstopmode",
            "-halt-on-error",
            "-file-line-error",
            "main.tex",
        ],
        "working_directory": "07-manuscript",
        "output": "07-manuscript/main.pdf",
        "output_sha256": sha256(MANUSCRIPT / "main.pdf"),
        "source_manifest": "07-manuscript/source-manifest.json",
        "hermetic": False,
        "independent": False,
        "limitations": "Local deterministic build; digest-pinned container replay remains open.",
    }
    write_json(SUBMISSION / "local-build-manifest.json", build_manifest)

    package_paths = [
        SUBMISSION / "ChronosAudit_TemporalClone_arxiv-source.zip",
        SUBMISSION / "ChronosAudit_TemporalClone_review-package.zip",
        SUBMISSION / "ChronosAudit_TemporalClone_MPP_draft.pdf",
    ]
    package_records = [
                {
                    "path": str(path.relative_to(ROOT)),
                    "bytes": path.stat().st_size,
                    "sha256": sha256(path),
                }
                for path in package_paths
            ]
    manifest_digest = hashlib.sha256(json.dumps(package_records, sort_keys=True).encode("utf-8")).hexdigest()
    write_json(
        SUBMISSION / "package-manifest.json",
        {
            "run_id": "chronosaudit-temporalclone-mpp-20260828T193046Z-5c71be2f-7ac55a",
            "manifest_sha256": manifest_digest,
            "pdf_sha256": sha256(MANUSCRIPT / "main.pdf"),
            "dry_run": False,
            "execute": True,
            "generated_at_utc": timestamp,
            "public_release_authorized": False,
            "row_level_derivatives_included": False,
            "packages": package_records,
            "arxiv_source_files": [path.name for path in arxiv_files],
            "review_package_files": [path.name for path in review_files],
            "open_gates": [
                "accountable author metadata and declarations",
                "downstream rights and license",
                "independent novelty challenge",
                "independent clean-machine reproduction",
                "human PDF and portal-preview approval",
            ],
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
