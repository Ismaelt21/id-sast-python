"""
html_report.py

HTML report generator for id-sast-python.

Responsibilities:
- Render a self-contained HTML report
- Present findings with a dashboard-like layout
- Keep the visual language consistent with the C# service
- Escape all user-controlled content

This module does not detect vulnerabilities. It only renders results.
"""

from __future__ import annotations

import html as html_lib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class HTMLReport:
    """Generates the HTML report for id-sast-python."""

    def __init__(self, output_dir: str = None):
        try:
            from config.settings import Settings

            default_dir = Settings.REPORTS_DIR
        except Exception:
            default_dir = "./reports/output"

        self.output_dir = Path(output_dir or default_dir)

    def generate(self, report_data: Dict, filename: str = None) -> str:
        """Generate and save the HTML report to disk."""
        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"py_sast_report_{timestamp}.html"

        output_path = self.output_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)

        html_content = self._build_html(report_data)
        output_path.write_text(html_content, encoding="utf-8")
        return str(output_path)

    def _build_html(self, report_data: Dict) -> str:
        metadata = report_data.get("metadata", {})
        project = report_data.get("project", {})
        stats = report_data.get("statistics", {})
        findings = report_data.get("findings", []) or []
        ai_analysis = report_data.get("ai_analysis", []) or []
        generated_rules = report_data.get("generated_rules", []) or []
        matched_rules = report_data.get("matched_rules", []) or []
        graphs = report_data.get("graphs", {}) or {}
        scan_summary = report_data.get("scan_summary", {}) or {}

        severity = self._normalize_severity(stats.get("severity", {}))
        total_findings = int(stats.get("total_findings", len(findings)))
        risk_level = self._derive_risk_level(severity)

        project_name = self._esc(project.get("name", "Unknown project"))
        total_files = self._esc(str(project.get("total_files", 0)))
        generated_at = self._esc(metadata.get("generated_at", _now_iso()))
        environment = self._esc(metadata.get("environment", "development"))
        version = self._esc(metadata.get("version", "unknown"))
        tool_name = self._esc(metadata.get("tool", "id-sast-python"))

        counts = {
            "AI": len(ai_analysis),
            "Rules": len(generated_rules),
            "Matches": len(matched_rules),
        }

        findings_html = self._build_findings(findings)
        ai_html = self._build_ai_analysis(ai_analysis)
        rules_html = self._build_rules(generated_rules)
        graph_html = self._build_graphs(graphs)

        year = datetime.utcnow().year
        scan_id = self._esc(str(scan_summary.get("scan_id", report_data.get("scan_id", "N/A"))))

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{tool_name} Security Report</title>
<style>
:root {{
    --bg: #0f172a;
    --bg-soft: #111827;
    --panel: #111827;
    --panel-alt: #1f2937;
    --line: rgba(255, 255, 255, 0.08);
    --text: #e5e7eb;
    --muted: #94a3b8;
    --primary: #38bdf8;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --chip: rgba(56, 189, 248, 0.12);
    --shadow: 0 24px 60px rgba(0, 0, 0, 0.35);
}}

* {{
    box-sizing: border-box;
}}

html {{
    scroll-behavior: smooth;
}}

body {{
    margin: 0;
    font-family: Inter, "Segoe UI", Roboto, Arial, sans-serif;
    background:
        radial-gradient(circle at top left, rgba(56, 189, 248, 0.16), transparent 32%),
        radial-gradient(circle at top right, rgba(34, 197, 94, 0.12), transparent 30%),
        linear-gradient(180deg, #020617 0%, var(--bg) 100%);
    color: var(--text);
}}

[data-theme="light"] {{
    --bg: #f8fafc;
    --bg-soft: #eef2ff;
    --panel: #ffffff;
    --panel-alt: #f8fafc;
    --line: rgba(15, 23, 42, 0.08);
    --text: #0f172a;
    --muted: #475569;
    --chip: rgba(14, 165, 233, 0.10);
    --shadow: 0 18px 42px rgba(15, 23, 42, 0.10);
    background:
        radial-gradient(circle at top left, rgba(14, 165, 233, 0.12), transparent 30%),
        radial-gradient(circle at top right, rgba(34, 197, 94, 0.08), transparent 28%),
        linear-gradient(180deg, #ffffff 0%, #eef2ff 100%);
}}

.shell {{
    width: min(1280px, calc(100% - 32px));
    margin: 0 auto;
    padding: 32px 0 48px;
}}

.hero {{
    position: relative;
    overflow: hidden;
    border: 1px solid var(--line);
    border-radius: 28px;
    padding: 32px;
    background:
        linear-gradient(145deg, rgba(17, 24, 39, 0.96), rgba(15, 23, 42, 0.84)),
        linear-gradient(145deg, rgba(56, 189, 248, 0.14), transparent 40%);
    box-shadow: var(--shadow);
    margin-bottom: 24px;
}}

[data-theme="light"] .hero {{
    background:
        linear-gradient(145deg, rgba(255, 255, 255, 0.98), rgba(248, 250, 252, 0.92)),
        linear-gradient(145deg, rgba(14, 165, 233, 0.08), transparent 38%);
}}

.eyebrow {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    font-size: 0.74rem;
    color: var(--primary);
    font-weight: 700;
}}

.eyebrow::before {{
    content: "";
    width: 10px;
    height: 10px;
    border-radius: 999px;
    background: var(--primary);
    box-shadow: 0 0 0 6px rgba(56, 189, 248, 0.15);
}}

.hero h1 {{
    margin: 12px 0 8px;
    font-size: clamp(2rem, 4vw, 3.6rem);
    line-height: 1.02;
    letter-spacing: -0.03em;
}}

.hero__subtitle {{
    margin: 0;
    max-width: 900px;
    color: var(--muted);
    font-size: 1rem;
}}

.chip-row {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 18px;
}}

.chip {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border: 1px solid var(--line);
    background: var(--chip);
    border-radius: 999px;
    font-size: 0.9rem;
    color: var(--text);
}}

.hero-grid {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
    margin-top: 26px;
}}

.metric-card,
.risk-card {{
    border: 1px solid var(--line);
    border-radius: 20px;
    background: rgba(255, 255, 255, 0.03);
    padding: 18px 18px 16px;
}}

[data-theme="light"] .metric-card,
[data-theme="light"] .risk-card {{
    background: rgba(255, 255, 255, 0.72);
}}

.metric-card span,
.risk-card span,
.mini-kpi span {{
    display: block;
    color: var(--muted);
    font-size: 0.86rem;
    margin-bottom: 10px;
}}

.metric-card strong,
.risk-card strong {{
    font-size: 1.6rem;
    letter-spacing: -0.02em;
}}

.risk-card {{
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}}

.risk-card.risk-clean strong {{ color: var(--low); }}
.risk-card.risk-low strong {{ color: var(--low); }}
.risk-card.risk-medium strong {{ color: var(--medium); }}
.risk-card.risk-high strong {{ color: var(--high); }}
.risk-card.risk-critical strong {{ color: var(--critical); }}

.metric-card small {{
    display: block;
    margin-top: 8px;
    color: var(--muted);
}}

.hero-footer {{
    margin-top: 18px;
    color: var(--muted);
    display: flex;
    flex-wrap: wrap;
    gap: 14px;
    font-size: 0.92rem;
}}

.top-controls {{
    display: flex;
    justify-content: flex-end;
    margin: 0 0 16px;
    gap: 10px;
    flex-wrap: wrap;
}}

.control-btn {{
    appearance: none;
    border: 1px solid var(--line);
    background: linear-gradient(180deg, rgba(56, 189, 248, 0.18), rgba(56, 189, 248, 0.08));
    color: var(--text);
    border-radius: 14px;
    padding: 12px 16px;
    cursor: pointer;
    font-weight: 700;
    letter-spacing: 0.01em;
    transition: transform 120ms ease, border-color 120ms ease, background 120ms ease;
}}

.control-btn:hover {{
    transform: translateY(-1px);
    border-color: rgba(56, 189, 248, 0.35);
}}

.control-btn--ghost {{
    background: transparent;
}}

.panel {{
    border: 1px solid var(--line);
    border-radius: 24px;
    background: rgba(255, 255, 255, 0.04);
    box-shadow: var(--shadow);
    margin-bottom: 22px;
    overflow: hidden;
}}

[data-theme="light"] .panel {{
    background: rgba(255, 255, 255, 0.78);
}}

.panel__header {{
    padding: 24px 24px 0;
    display: flex;
    justify-content: space-between;
    gap: 16px;
    align-items: end;
}}

.panel__header h2 {{
    margin: 0 0 6px;
    font-size: 1.4rem;
}}

.panel__header p {{
    margin: 0;
    color: var(--muted);
}}

.panel__body {{
    padding: 24px;
}}

.stats-grid {{
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 14px;
    padding: 24px;
}}

.stat {{
    border: 1px solid var(--line);
    border-radius: 18px;
    background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02));
    padding: 16px;
}}

[data-theme="light"] .stat {{
    background: rgba(248, 250, 252, 0.88);
}}

.stat span {{
    display: block;
    color: var(--muted);
    font-size: 0.82rem;
    margin-bottom: 10px;
}}

.stat strong {{
    display: block;
    font-size: 1.45rem;
    letter-spacing: -0.02em;
}}

.stat small {{
    display: block;
    color: var(--muted);
    margin-top: 6px;
}}

.toolbar {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    padding: 18px 24px 0;
    align-items: center;
}}

.toolbar input {{
    flex: 1;
    min-width: 260px;
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 13px 14px;
    background: rgba(15, 23, 42, 0.35);
    color: var(--text);
}}

[data-theme="light"] .toolbar input {{
    background: rgba(255, 255, 255, 0.92);
}}

.filter-row {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    padding: 14px 24px 24px;
}}

.filter-chip {{
    border: 1px solid var(--line);
    background: transparent;
    color: var(--text);
    border-radius: 999px;
    padding: 10px 14px;
    cursor: pointer;
    font-weight: 700;
}}

.filter-chip.active {{
    background: rgba(56, 189, 248, 0.18);
    border-color: rgba(56, 189, 248, 0.30);
}}

.finding-list {{
    padding: 0 24px 24px;
    display: grid;
    gap: 16px;
}}

.finding {{
    border: 1px solid var(--line);
    border-radius: 20px;
    background: rgba(255, 255, 255, 0.03);
    padding: 18px;
}}

[data-theme="light"] .finding {{
    background: rgba(248, 250, 252, 0.9);
}}

.finding__top {{
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 12px;
    align-items: start;
}}

.finding__title {{
    margin: 0;
    font-size: 1.1rem;
}}

.badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 12px;
    border-radius: 999px;
    font-size: 0.84rem;
    font-weight: 700;
    border: 1px solid var(--line);
}}

.badge.critical {{ background: rgba(239, 68, 68, 0.16); color: #fecaca; }}
.badge.high {{ background: rgba(249, 115, 22, 0.16); color: #fed7aa; }}
.badge.medium {{ background: rgba(234, 179, 8, 0.16); color: #fde68a; }}
.badge.low {{ background: rgba(34, 197, 94, 0.16); color: #bbf7d0; }}

[data-theme="light"] .badge.critical {{ color: #b91c1c; }}
[data-theme="light"] .badge.high {{ color: #c2410c; }}
[data-theme="light"] .badge.medium {{ color: #a16207; }}
[data-theme="light"] .badge.low {{ color: #15803d; }}

.finding__meta {{
    margin-top: 12px;
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
}}

.meta-item {{
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 12px 14px;
}}

.meta-item span {{
    display: block;
    color: var(--muted);
    font-size: 0.8rem;
    margin-bottom: 6px;
}}

.meta-item strong {{
    font-size: 0.95rem;
    word-break: break-word;
}}

.finding__desc {{
    margin: 14px 0 0;
    color: var(--muted);
    line-height: 1.65;
}}

.code {{
    margin-top: 14px;
    background: #020617;
    border: 1px solid rgba(148, 163, 184, 0.16);
    border-radius: 16px;
    padding: 14px;
    overflow-x: auto;
    color: #e2e8f0;
    font-family: Consolas, "Courier New", monospace;
    font-size: 0.9rem;
}}

[data-theme="light"] .code {{
    background: #0f172a;
}}

.mini-grid {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
    padding: 0 24px 24px;
}}

.mini-kpi {{
    border: 1px solid var(--line);
    border-radius: 18px;
    padding: 16px;
    background: rgba(255, 255, 255, 0.03);
}}

[data-theme="light"] .mini-kpi {{
    background: rgba(248, 250, 252, 0.88);
}}

.mini-kpi strong {{
    display: block;
    font-size: 1.25rem;
}}

.graph-grid {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
    padding: 0 24px 24px;
}}

.graph-card {{
    border: 1px solid var(--line);
    border-radius: 18px;
    padding: 16px;
    background: rgba(255, 255, 255, 0.03);
}}

.graph-card strong {{
    display: block;
    font-size: 1.2rem;
    margin-top: 6px;
}}

.empty {{
    color: var(--muted);
    padding: 24px;
    text-align: center;
}}

.footer {{
    margin-top: 28px;
    padding: 22px;
    text-align: center;
    color: var(--muted);
}}

@media (max-width: 1080px) {{
    .stats-grid,
    .hero-grid,
    .mini-grid,
    .graph-grid {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }}
}}

@media (max-width: 760px) {{
    .shell {{
        width: min(100% - 20px, 1280px);
        padding: 20px 0 28px;
    }}

    .hero,
    .panel {{
        border-radius: 22px;
    }}

    .hero,
    .panel__header,
    .panel__body,
    .stats-grid,
    .finding-list,
    .mini-grid,
    .graph-grid {{
        padding-left: 16px;
        padding-right: 16px;
    }}

    .hero-grid,
    .stats-grid,
    .mini-grid,
    .graph-grid,
    .finding__meta {{
        grid-template-columns: 1fr;
    }}

    .toolbar {{
        padding-left: 16px;
        padding-right: 16px;
    }}
}}
</style>
</head>
<body data-theme="dark">
<div class="shell">
    <section class="hero">
        <span class="eyebrow">id-sast-python</span>
        <h1>{project_name}</h1>
        <p class="hero__subtitle">Static security report for Python sources, with API and CLI parity across the SAST suite.</p>

        <div class="chip-row">
            <span class="chip">Tool: {tool_name}</span>
            <span class="chip">Version: {version}</span>
            <span class="chip">Environment: {environment}</span>
            <span class="chip">Scan: {scan_id}</span>
        </div>

        <div class="hero-grid">
            <div class="risk-card risk-{risk_level.lower()}">
                <span>Risk level</span>
                <strong>{self._esc(risk_level)}</strong>
            </div>
            <div class="metric-card">
                <span>Total findings</span>
                <strong>{total_findings}</strong>
                <small>{severity.get("CRITICAL", 0)} critical, {severity.get("HIGH", 0)} high</small>
            </div>
            <div class="metric-card">
                <span>Files scanned</span>
                <strong>{total_files}</strong>
                <small>Generated at {generated_at}</small>
            </div>
        </div>

        <div class="hero-footer">
            <span>AI findings: {counts["AI"]}</span>
            <span>Generated rules: {counts["Rules"]}</span>
            <span>Matched rules: {counts["Matches"]}</span>
        </div>
    </section>

    <div class="top-controls">
        <button class="control-btn" id="theme-toggle" type="button">Toggle theme</button>
        <button class="control-btn control-btn--ghost" id="print-report" type="button">Print / PDF</button>
    </div>

    <section class="panel">
        <div class="panel__header">
            <div>
                <h2>Executive Summary</h2>
                <p>Quick view of the analysis scope and the severity distribution.</p>
            </div>
        </div>
        <div class="stats-grid">
            <div class="stat"><span>Critical</span><strong>{severity["CRITICAL"]}</strong></div>
            <div class="stat"><span>High</span><strong>{severity["HIGH"]}</strong></div>
            <div class="stat"><span>Medium</span><strong>{severity["MEDIUM"]}</strong></div>
            <div class="stat"><span>Low</span><strong>{severity["LOW"]}</strong></div>
            <div class="stat"><span>Findings</span><strong>{total_findings}</strong></div>
            <div class="stat"><span>Project</span><strong>{project_name}</strong></div>
        </div>
    </section>

    <section class="panel">
        <div class="panel__header">
            <div>
                <h2>Findings</h2>
                <p>Detailed vulnerabilities with source, sink, confidence and remediation hints.</p>
            </div>
        </div>
        <div class="toolbar">
            <input id="search-input" type="search" placeholder="Search findings, source, sink, vulnerability..." />
        </div>
        <div class="filter-row">
            <button class="filter-chip active" data-filter="ALL" type="button">All</button>
            <button class="filter-chip" data-filter="CRITICAL" type="button">Critical</button>
            <button class="filter-chip" data-filter="HIGH" type="button">High</button>
            <button class="filter-chip" data-filter="MEDIUM" type="button">Medium</button>
            <button class="filter-chip" data-filter="LOW" type="button">Low</button>
        </div>
        <div class="finding-list" id="finding-list">
            {findings_html}
        </div>
    </section>

    <section class="panel">
        <div class="panel__header">
            <div>
                <h2>AI Analysis</h2>
                <p>Semantic validation results produced by the analysis pipeline.</p>
            </div>
        </div>
        <div class="mini-grid">
            <div class="mini-kpi">
                <span>Analyses</span>
                <strong>{len(ai_analysis)}</strong>
            </div>
            <div class="mini-kpi">
                <span>Rules generated</span>
                <strong>{len(generated_rules)}</strong>
            </div>
            <div class="mini-kpi">
                <span>Rules matched</span>
                <strong>{len(matched_rules)}</strong>
            </div>
        </div>
        {ai_html}
    </section>

    <section class="panel">
        <div class="panel__header">
            <div>
                <h2>Generated Rules</h2>
                <p>Reusable semantic rules inferred from the scan context.</p>
            </div>
        </div>
        {rules_html}
    </section>

    <section class="panel">
        <div class="panel__header">
            <div>
                <h2>Graph Overview</h2>
                <p>Compact view of AST, CFG and DFG availability.</p>
            </div>
        </div>
        {graph_html}
    </section>

    <div class="footer">id-sast-python &copy; {year}</div>
</div>

<script>
(function() {{
    const root = document.body;
    const toggle = document.getElementById('theme-toggle');
    const printBtn = document.getElementById('print-report');
    const searchInput = document.getElementById('search-input');
    const cards = Array.from(document.querySelectorAll('[data-finding-card]'));
    const chips = Array.from(document.querySelectorAll('[data-filter]'));

    let activeFilter = 'ALL';

    function applyFilters() {{
        const query = (searchInput?.value || '').trim().toLowerCase();
        cards.forEach(card => {{
            const severity = (card.getAttribute('data-severity') || '').toUpperCase();
            const text = (card.innerText || '').toLowerCase();
            const matchesSeverity = activeFilter === 'ALL' || severity === activeFilter;
            const matchesQuery = !query || text.includes(query);
            card.style.display = matchesSeverity && matchesQuery ? '' : 'none';
        }});
    }}

    chips.forEach(chip => {{
        chip.addEventListener('click', () => {{
            activeFilter = chip.getAttribute('data-filter') || 'ALL';
            chips.forEach(item => item.classList.toggle('active', item === chip));
            applyFilters();
        }});
    }});

    if (searchInput) {{
        searchInput.addEventListener('input', applyFilters);
    }}

    if (toggle) {{
        toggle.addEventListener('click', () => {{
            const current = root.getAttribute('data-theme') || 'dark';
            root.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
            toggle.textContent = current === 'dark' ? 'Toggle dark' : 'Toggle light';
        }});
    }}

    if (printBtn) {{
        printBtn.addEventListener('click', () => window.print());
    }}
}})();
</script>
</body>
</html>"""

    def _build_findings(self, findings: List[Dict]) -> str:
        if not findings:
            return '<div class="empty">No vulnerabilities detected.</div>'

        blocks: List[str] = []
        for idx, finding in enumerate(findings, start=1):
            severity = self._normalize_severity_label(finding.get("severity", "LOW"))
            vuln_type = self._esc(finding.get("vulnerability") or finding.get("vulnerability_type", "UNKNOWN"))
            description = self._esc(finding.get("description", "No description"))
            file_path = self._esc(finding.get("file", "unknown"))
            line = self._esc(str(finding.get("line", "?")))
            source = self._esc(finding.get("source", "unknown"))
            sink = self._esc(finding.get("sink_label") or finding.get("sink", "unknown"))
            confidence = self._esc(str(finding.get("confidence", 0)))
            cwe = self._esc(finding.get("cwe_id") or finding.get("cwe") or "")
            recommendation = self._esc(finding.get("recommendation", ""))
            code = self._esc(finding.get("code", ""))
            path = finding.get("path") or finding.get("taint_path") or []
            path_html = self._esc(" -> ".join(map(str, path))) if path else ""

            blocks.append(
                f"""
<article class="finding" data-finding-card data-severity="{severity}">
    <div class="finding__top">
        <div>
            <p class="finding__title">#{idx} {vuln_type}</p>
            <p class="finding__desc">{description}</p>
        </div>
        <span class="badge {severity.lower()}">{severity}</span>
    </div>

    <div class="finding__meta">
        <div class="meta-item"><span>File</span><strong>{file_path}</strong></div>
        <div class="meta-item"><span>Line</span><strong>{line}</strong></div>
        <div class="meta-item"><span>Confidence</span><strong>{confidence}</strong></div>
    </div>

    <div class="finding__meta">
        <div class="meta-item"><span>Source</span><strong>{source}</strong></div>
        <div class="meta-item"><span>Sink</span><strong>{sink}</strong></div>
        <div class="meta-item"><span>CWE</span><strong>{cwe or 'N/A'}</strong></div>
    </div>

    {f'<p class="finding__desc"><strong>Taint path:</strong> {path_html}</p>' if path_html else ''}
    {f'<p class="finding__desc"><strong>Recommendation:</strong> {recommendation}</p>' if recommendation else ''}
    {f'<pre class="code">{code}</pre>' if code else ''}
</article>"""
            )

        return "\n".join(blocks)

    def _build_ai_analysis(self, ai_analysis: List[Dict]) -> str:
        if not ai_analysis:
            return '<div class="empty">No AI analysis generated for this scan.</div>'

        blocks: List[str] = []
        for idx, item in enumerate(ai_analysis, start=1):
            classification = self._esc(item.get("classification", "UNKNOWN"))
            vuln = self._esc(item.get("vulnerability_type", "UNKNOWN"))
            risk = self._esc(item.get("contextual_risk", "UNKNOWN"))
            confidence = self._esc(str(item.get("semantic_confidence", 0)))
            reasoning = self._esc(item.get("reasoning", ""))

            blocks.append(
                f"""
<div class="finding">
    <div class="finding__top">
        <div>
            <p class="finding__title">AI result #{idx} - {vuln}</p>
            <p class="finding__desc">{reasoning}</p>
        </div>
        <span class="badge medium">{classification}</span>
    </div>
    <div class="finding__meta">
        <div class="meta-item"><span>Risk</span><strong>{risk}</strong></div>
        <div class="meta-item"><span>Confidence</span><strong>{confidence}</strong></div>
        <div class="meta-item"><span>Detected</span><strong>{self._esc(str(item.get('vulnerability_detected', False)))}</strong></div>
    </div>
</div>"""
            )

        return "\n".join(blocks)

    def _build_rules(self, generated_rules: List[Dict]) -> str:
        if not generated_rules:
            return '<div class="empty">No generated rules in this scan.</div>'

        blocks: List[str] = []
        for idx, rule in enumerate(generated_rules, start=1):
            blocks.append(
                f"""
<div class="finding">
    <div class="finding__top">
        <div>
            <p class="finding__title">Rule #{idx} - {self._esc(rule.get("pattern_name", "UNKNOWN_pattern"))}</p>
            <p class="finding__desc">Generated from {self._esc(rule.get("source_pattern", "UNKNOWN"))} -> {self._esc(rule.get("sink_pattern", "UNKNOWN"))}</p>
        </div>
        <span class="badge low">Rule</span>
    </div>
    <div class="finding__meta">
        <div class="meta-item"><span>Vulnerability</span><strong>{self._esc(rule.get("vulnerability_type", "UNKNOWN"))}</strong></div>
        <div class="meta-item"><span>Confidence</span><strong>{self._esc(str(rule.get("confidence", 0)))}</strong></div>
        <div class="meta-item"><span>Risk</span><strong>{self._esc(rule.get("risk", "MEDIUM"))}</strong></div>
    </div>
</div>"""
            )

        return "\n".join(blocks)

    def _build_graphs(self, graphs: Dict) -> str:
        if not graphs:
            return '<div class="empty">No graph summary available.</div>'

        cards = []
        for graph_name in ("ast", "cfg", "dfg"):
            graph = graphs.get(graph_name, {}) or {}
            cards.append(
                f"""
<div class="graph-card">
    <span>{graph_name.upper()}</span>
    <strong>{'Available' if graph.get('available') else 'Not available'}</strong>
    <small>Nodes: {graph.get('nodes', 0)} · Edges: {graph.get('edges', 0)}</small>
</div>"""
            )

        return f'<div class="graph-grid">{"".join(cards)}</div>'

    @staticmethod
    def _normalize_severity(severity: Dict[str, int]) -> Dict[str, int]:
        return {
            "CRITICAL": int(severity.get("CRITICAL", 0)),
            "HIGH": int(severity.get("HIGH", 0)),
            "MEDIUM": int(severity.get("MEDIUM", 0)),
            "LOW": int(severity.get("LOW", 0)),
        }

    @staticmethod
    def _normalize_severity_label(value: str) -> str:
        normalized = str(value or "LOW").upper()
        return normalized if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "LOW"

    @staticmethod
    def _derive_risk_level(severity: Dict[str, int]) -> str:
        if severity.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        if severity.get("HIGH", 0) > 0:
            return "HIGH"
        if severity.get("MEDIUM", 0) > 0:
            return "MEDIUM"
        if severity.get("LOW", 0) > 0:
            return "LOW"
        return "CLEAN"

    @staticmethod
    def _esc(value: Any) -> str:
        return html_lib.escape(str(value), quote=True)

    def generate_minimal(self, findings: List[Dict]) -> str:
        total = len(findings)
        return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>id-sast-python Minimal Report</title></head>
<body>
<h1>id-sast-python Minimal Report</h1>
<p>Total Findings: {total}</p>
</body>
</html>"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    report_data = {
        "metadata": {"generated_at": datetime.utcnow().isoformat()},
        "project": {"name": "test-project", "total_files": 3},
        "statistics": {"severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}},
        "findings": [
            {
                "vulnerability": "COMMAND_INJECTION",
                "severity": "CRITICAL",
                "source": "input",
                "sink": "os.system@5",
                "sink_label": "os.system",
                "confidence": 0.90,
                "description": "Untrusted input reaches os.system",
                "file": "app.py",
                "line": 5,
                "cwe_id": "CWE-78",
                "recommendation": "Avoid shell execution with user input.",
                "code": "os.system(user_input)  # <dangerous>",
            }
        ],
    }

    reporter = HTMLReport(output_dir="/tmp/sast_reports")
    path = reporter.generate(report_data)
    print(f"Report saved to: {path}")
