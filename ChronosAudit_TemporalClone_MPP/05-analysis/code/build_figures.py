#!/usr/bin/env python3
"""Generate dependency-free, self-contained SVG publication figures."""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
from pathlib import Path
from typing import Iterable


BLUE = "#0072B2"
ORANGE = "#E69F00"
GREEN = "#009E73"
PURPLE = "#CC79A7"
GRAY = "#666666"


def read_cases(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def svg_document(width: int, height: int, title: str, description: str, body: Iterable[str]) -> str:
    content = "\n".join(body)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">\n'
        f'  <title id="title">{html.escape(title)}</title>\n'
        f'  <desc id="desc">{html.escape(description)}</desc>\n'
        '  <rect width="100%" height="100%" fill="white"/>\n'
        '  <style>text{font-family:Arial,Helvetica,sans-serif;fill:#111} .axis{stroke:#111;stroke-width:2} .grid{stroke:#ddd;stroke-width:1} .tick{font-size:20px} .label{font-size:23px} .title{font-size:28px;font-weight:700} .value{font-size:20px;font-weight:700}</style>\n'
        f'{content}\n</svg>\n'
    )


def text(x: float, y: float, value: str, css: str = "tick", anchor: str = "middle", rotate: int | None = None) -> str:
    transform = f' transform="rotate({rotate} {x:.1f} {y:.1f})"' if rotate is not None else ""
    return f'  <text x="{x:.1f}" y="{y:.1f}" class="{css}" text-anchor="{anchor}"{transform}>{html.escape(value)}</text>'


def build_temporal(summary: dict, output: Path) -> None:
    width, height = 1200, 800
    left, right, top, bottom = 130, 50, 100, 130
    plot_w, plot_h = width - left - right, height - top - bottom
    labels = ["1 hour", "24 hours", "7 days", "30 days"]
    keys = ["eligible_1h", "eligible_24h", "eligible_7d", "eligible_30d"]
    records = [summary["temporal_eligibility"][key] for key in keys]
    n_cases = int(summary["cohort"]["n_cases"])
    body = [text(width / 2, 52, "Contract existence at pre-incident landmarks", "title")]
    for fraction in (0, 0.25, 0.5, 0.75, 1.0):
        y = top + plot_h * (1 - fraction)
        body.append(f'  <line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" class="grid"/>')
        body.append(text(left - 16, y + 7, f"{int(100*fraction)}%", anchor="end"))
    body.extend([
        f'  <line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}" class="axis"/>',
        f'  <line x1="{left}" y1="{top+plot_h}" x2="{width-right}" y2="{top+plot_h}" class="axis"/>',
        text(38, top + plot_h / 2, f"Eligible fraction (N={n_cases})", "label", rotate=-90),
    ])
    slot = plot_w / len(labels)
    bar_w = slot * 0.56
    for index, (label, record) in enumerate(zip(labels, records)):
        proportion = float(record["proportion"])
        x = left + slot * (index + 0.5)
        y = top + plot_h * (1 - proportion)
        bar_h = plot_h * proportion
        body.append(f'  <rect x="{x-bar_w/2:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" fill="{BLUE}" stroke="#111" stroke-width="2"/>')
        low_y = top + plot_h * (1 - float(record["wilson_95_low"]))
        high_y = top + plot_h * (1 - float(record["wilson_95_high"]))
        body.extend([
            f'  <line x1="{x:.1f}" y1="{low_y:.1f}" x2="{x:.1f}" y2="{high_y:.1f}" stroke="#111" stroke-width="3"/>',
            f'  <line x1="{x-12:.1f}" y1="{low_y:.1f}" x2="{x+12:.1f}" y2="{low_y:.1f}" stroke="#111" stroke-width="3"/>',
            f'  <line x1="{x-12:.1f}" y1="{high_y:.1f}" x2="{x+12:.1f}" y2="{high_y:.1f}" stroke="#111" stroke-width="3"/>',
            text(x, max(82, y - 18), f"{record['n']}/{n_cases}", "value"),
            text(x, top + plot_h + 38, label, "label"),
        ])
    output.write_text(svg_document(width, height, "Temporal eligibility", "Bar chart of the fraction of benchmark contracts that existed at one hour, 24 hours, seven days, and 30 days before the recorded incident, with Wilson 95 percent intervals.", body), encoding="utf-8")


def build_identity(summary: dict, output: Path) -> None:
    width, height = 2200, 850
    labels = ["Chain-address", "Address only", "Exact runtime", "Metadata-stripped"]
    keys = ["chain_address", "address_only", "runtime_bytecode", "metadata_stripped_bytecode"]
    records = [summary["identity_abstractions"][key] for key in keys]
    colors = [GRAY, GRAY, ORANGE, GREEN]
    body = [text(width / 2, 48, "Identity abstraction sensitivity", "title")]

    for panel, metric, panel_title, maximum in (
        (0, "duplicate_rows", "A. Rows in duplicate groups", 65),
        (1, "unique_identities", "B. Unique identities", int(summary["cohort"]["n_cases"]) + 25),
    ):
        panel_x = 80 + panel * 1080
        panel_w, panel_h, top = 980, 610, 105
        body.append(text(panel_x + panel_w / 2, 86, panel_title, "label"))
        body.extend([
            f'  <line x1="{panel_x+85}" y1="{top}" x2="{panel_x+85}" y2="{top+panel_h}" class="axis"/>',
            f'  <line x1="{panel_x+85}" y1="{top+panel_h}" x2="{panel_x+panel_w}" y2="{top+panel_h}" class="axis"/>',
        ])
        for fraction in (0, 0.25, 0.5, 0.75, 1.0):
            value = maximum * fraction
            y = top + panel_h * (1 - fraction)
            body.append(f'  <line x1="{panel_x+85}" y1="{y:.1f}" x2="{panel_x+panel_w}" y2="{y:.1f}" class="grid"/>')
            body.append(text(panel_x + 70, y + 7, f"{value:.0f}", anchor="end"))
        slot = (panel_w - 100) / 4
        for index, (label, record, color) in enumerate(zip(labels, records, colors)):
            value = int(record[metric])
            x = panel_x + 100 + slot * (index + 0.5)
            bar_w = slot * 0.56
            bar_h = panel_h * value / maximum
            y = top + panel_h - bar_h
            body.extend([
                f'  <rect x="{x-bar_w/2:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" fill="{color}" stroke="#111" stroke-width="2"/>',
                text(x, max(top + 18, y - 12), str(value), "value"),
                text(x, top + panel_h + 34, label, "tick", rotate=-22),
            ])
    output.write_text(svg_document(width, height, "Identity abstraction sensitivity", "Two-panel bar chart showing rows assigned to duplicate groups and unique identity counts under chain-address, address-only, exact runtime bytecode, and metadata-stripped runtime bytecode identities.", body), encoding="utf-8")


def build_ecdf(cases: list[dict[str, str]], output: Path) -> None:
    width, height = 1200, 800
    left, right, top, bottom = 135, 55, 100, 130
    plot_w, plot_h = width - left - right, height - top - bottom
    ages = sorted(float(row["deployment_to_incident_hours"]) for row in cases)
    min_log, max_log = math.log10(min(ages)), math.log10(max(ages))

    def sx(value: float) -> float:
        return left + plot_w * (math.log10(value) - min_log) / (max_log - min_log)

    def sy(value: float) -> float:
        return top + plot_h * (1 - value)

    body = [text(width / 2, 52, "Deployment-age distribution", "title")]
    for fraction in (0, 0.25, 0.5, 0.75, 1.0):
        y = sy(fraction)
        body.append(f'  <line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" class="grid"/>')
        body.append(text(left - 15, y + 7, f"{int(100*fraction)}%", anchor="end"))
    body.extend([
        f'  <line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}" class="axis"/>',
        f'  <line x1="{left}" y1="{top+plot_h}" x2="{width-right}" y2="{top+plot_h}" class="axis"/>',
        text(38, top + plot_h / 2, "Cumulative fraction", "label", rotate=-90),
        text(left + plot_w / 2, height - 35, "Deployment-to-incident age (hours; log scale)", "label"),
    ])
    points = " ".join(f"{sx(age):.1f},{sy((index+1)/len(ages)):.1f}" for index, age in enumerate(ages))
    body.append(f'  <polyline points="{points}" fill="none" stroke="{PURPLE}" stroke-width="4"/>')
    for value, label, dash in ((24, "24h", "4 6"), (168, "7d", "12 7"), (720, "30d", "16 5 3 5")):
        x = sx(value)
        body.extend([
            f'  <line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{top+plot_h}" stroke="{GRAY}" stroke-width="2" stroke-dasharray="{dash}"/>',
            text(x + 6, top + 25, label, anchor="start"),
        ])
    for exponent in range(math.ceil(min_log), math.floor(max_log) + 1):
        value = 10 ** exponent
        x = sx(value)
        body.append(text(x, top + plot_h + 38, f"10^{exponent}"))
    output.write_text(svg_document(width, height, "Deployment-age distribution", "Empirical cumulative distribution of deployment-to-incident age on a logarithmic hour scale, with vertical lines at 24 hours, seven days, and 30 days.", body), encoding="utf-8")


def build_figures(summary_path: Path, cases_path: Path, output_dir: Path) -> None:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    cases = read_cases(cases_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    build_temporal(summary, output_dir / "figure1-temporal-eligibility.svg")
    build_identity(summary, output_dir / "figure2-identity-sensitivity.svg")
    build_ecdf(cases, output_dir / "figure3-deployment-age-ecdf.svg")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    build_figures(args.summary, args.cases, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
