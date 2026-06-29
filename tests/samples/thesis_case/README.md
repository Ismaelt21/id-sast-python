Thesis benchmark corpus for positive detection.

This corpus is intentionally separated from `samples/vulnerable/` so the thesis
validation set can evolve independently from the general training samples.

Expected detections today:
- SQL_INJECTION
- PATH_TRAVERSAL
- SSRF
- XSS

Known capability gaps in the current pipeline:
- OPEN_REDIRECT
- XXE

Run with:
- `python tests/run_thesis_benchmarks.py`
- `python -m pytest -q tests/test_thesis_benchmarks.py` if `pytest` is installed
