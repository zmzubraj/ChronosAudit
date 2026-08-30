# Analysis replay report

Date: 2026-08-29  
Executor: Codex root integration owner  
Independence: **No — local mechanical replay only**

ANALYSIS REPLAY PASSED: TRUE  
FIGURE REPLAY PASSED: TRUE  
PHASE PROMOTION: NOT PERFORMED

Commands:

```text
python3 -m unittest discover -s 05-analysis/code -p 'test_*.py'
python3 05-analysis/code/derive_mpp_results.py
python3 05-analysis/code/build_tables.py
python3 05-analysis/code/build_figures.py
latexmk -pdf -interaction=nonstopmode -halt-on-error -file-line-error main.tex
```

Observed canonical outputs:

- 417/417 eligible at 1 hour and 24 hours;
- 352/417 at 7 days;
- 275/417 at 30 days;
- duplicate-group rows: 14 address, 46 exact runtime, 56 stripped runtime;
- any specified proxy indicator: 67/417.

All seven local analysis/table/figure tests passed. This replay establishes internal repeatability only; a differently owned clean-machine replay remains required.
