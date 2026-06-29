Thesis benchmark corpus for negative controls.

This corpus intentionally mirrors the vulnerable cases with:
- one vulnerable variant,
- one safe variant,
- one innocuous helper that looks similar but does not reach a sink.

The goal is to measure false positives and calibration, not just recall.

Expected behavior today:
- supported categories should flag the vulnerable variant and keep the safe/helper variants clean;
- `OPEN_REDIRECT` and `XXE` may still surface as known gaps depending on the current DFG sink model.

Run with:
- `python tests/run_thesis_benchmarks.py`
- `python -m pytest -q tests/test_thesis_benchmarks.py` if `pytest` is installed
