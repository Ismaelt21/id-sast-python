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
        project_path = self._esc(project.get("path", ""))
        total_files = self._esc(str(project.get("total_files", 0)))
        generated_at = self._esc(metadata.get("generated_at", _now_iso()))
        environment = self._esc(metadata.get("environment", "development"))
        version = self._esc(metadata.get("version", "unknown"))
        tool_name = self._esc(metadata.get("tool", "id-sast-python"))

        methods_count = self._count_unique_finding_values(
            findings,
            ("method", "method_name", "function", "function_name", "callee"),
        )
        classes_count = self._count_unique_finding_values(
            findings,
            ("class", "class_name", "declaring_class", "type_name"),
        )

        false_positives_removed = int(
            scan_summary.get(
                "false_positives_removed",
                stats.get("false_positives_removed", 0) or 0,
            )
        )
        false_positive_rate = self._format_percentage(
            false_positives_removed, total_findings
        )

        frameworks_detected = self._extract_frameworks(findings)
        frameworks_text = self._esc(", ".join(frameworks_detected)) if frameworks_detected else "No disponible"
        analysis_metrics = self._build_analysis_metrics(report_data, findings, graphs)
        top_files_html = self._esc(self._build_top_files(findings))
        top_types_html = self._esc(self._build_top_types(stats))
        frameworks_detected_html = self._esc(self._build_frameworks_detected(findings, project))
        duration_text = self._esc(self._format_duration(scan_summary))

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
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{tool_name} Security Report</title>
<style>
:root {{
    --bg: #07111d;
    --bg-soft: #0d1728;
    --panel: rgba(14, 22, 38, 0.92);
    --panel-alt: rgba(17, 27, 46, 0.98);
    --line: rgba(159, 176, 204, 0.16);
    --text: #edf4ff;
    --muted: #a8b7cd;
    --primary: #8be0ff;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #f59e0b;
    --low: #22c55e;
    --chip: rgba(139, 224, 255, 0.08);
    --shadow: 0 18px 42px rgba(0, 0, 0, 0.22);
}}

* {{
    box-sizing: border-box;
}}

html {{
    scroll-behavior: smooth;
}}

body {{
    margin: 0;
    font-family: "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
    background:
        radial-gradient(circle at top left, rgba(139, 224, 255, 0.16), transparent 30%),
        radial-gradient(circle at top right, rgba(249, 115, 22, 0.10), transparent 28%),
        linear-gradient(180deg, #0b1627 0%, var(--bg) 100%);
    color: var(--text);
}}

[data-theme="light"] {{
    --bg: #eef4fb;
    --bg-soft: #ffffff;
    --panel: rgba(255, 255, 255, 0.92);
    --panel-alt: rgba(255, 255, 255, 0.98);
    --line: rgba(15, 23, 42, 0.10);
    --text: #0f172a;
    --muted: #516176;
    --chip: rgba(14, 165, 233, 0.10);
    --shadow: 0 18px 42px rgba(15, 23, 42, 0.10);
    background:
        radial-gradient(circle at top left, rgba(14, 165, 233, 0.10), transparent 30%),
        radial-gradient(circle at top right, rgba(251, 146, 60, 0.08), transparent 28%),
        linear-gradient(180deg, #f9fbff 0%, #edf3fb 42%, #f6f8fc 100%);
}}

.shell {{
    width: min(1360px, calc(100% - 32px));
    margin: 28px auto 64px;
    padding: 0;
    display: grid;
    gap: 18px;
}}

.hero {{
    position: relative;
    overflow: hidden;
    border: 1px solid var(--line);
    border-radius: 24px;
    padding: 30px;
    background:
        linear-gradient(180deg, var(--panel-alt), var(--panel)),
        linear-gradient(145deg, rgba(139, 224, 255, 0.08), transparent 40%);
    box-shadow:
        0 18px 42px rgba(0, 0, 0, 0.22),
        inset 0 1px 0 rgba(255, 255, 255, 0.03);
    backdrop-filter: blur(16px);
}}

[data-theme="light"] .hero {{
    background:
        linear-gradient(180deg, var(--panel-alt), var(--panel)),
        linear-gradient(145deg, rgba(139, 224, 255, 0.06), transparent 38%);
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
    border-radius: 16px;
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
    font-size: 2rem;
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
    background: linear-gradient(180deg, var(--panel-alt), var(--panel));
    box-shadow:
        0 18px 42px rgba(0, 0, 0, 0.22),
        inset 0 1px 0 rgba(255, 255, 255, 0.03);
    backdrop-filter: blur(16px);
    margin-bottom: 0;
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
    border-radius: 16px;
    background: rgba(255, 255, 255, 0.03);
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
    backdrop-filter: blur(10px);
}}

[data-theme="light"] .finding {{
    background: rgba(248, 250, 252, 0.88);
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
.badge.medium {{ background: rgba(245, 158, 11, 0.16); color: #fde68a; }}
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
    background: rgba(255, 255, 255, 0.02);
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

.finding__lede {{
    margin: 8px 0 0;
    color: var(--muted);
    line-height: 1.55;
}}

.finding__summary {{
    margin-top: 12px;
    padding: 12px 14px;
    border: 1px solid var(--line);
    border-radius: 16px;
    background: rgba(255, 255, 255, 0.02);
    color: var(--muted);
    line-height: 1.55;
}}

.finding__meta--single {{
    grid-template-columns: repeat(5, minmax(0, 1fr));
}}

.section-block {{
    margin-top: 16px;
}}

.section-block h3 {{
    margin: 0 0 8px;
    font-size: 0.95rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--primary);
}}

.section-block p {{
    margin: 0;
    color: var(--text);
    line-height: 1.65;
}}

.section-card-grid {{
    margin-top: 16px;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
}}

.section-card {{
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 14px;
    background: rgba(255, 255, 255, 0.02);
}}

.section-card h3 {{
    margin: 0 0 8px;
    font-size: 0.95rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--primary);
}}

.section-card p {{
    margin: 0;
    color: var(--text);
    line-height: 1.55;
}}

.references-list {{
    margin: 0;
    padding-left: 20px;
    color: var(--muted);
    line-height: 1.6;
}}

.finding__meta-line {{
    margin-top: 10px;
    color: var(--muted);
    font-size: 0.95rem;
}}

.summary-grid--csharp {{
    grid-template-columns: repeat(6, minmax(0, 1fr));
}}

.summary-grid--metrics {{
    grid-template-columns: repeat(8, minmax(0, 1fr));
}}

.mini-grid--dense {{
    grid-template-columns: repeat(4, minmax(0, 1fr));
}}

.code {{
    margin-top: 14px;
    background: rgba(10, 16, 32, 0.88);
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 14px;
    overflow-x: auto;
    color: #e2e8f0;
    font-family: Consolas, "SFMono-Regular", monospace;
    font-size: 0.9rem;
}}

[data-theme="light"] .code {{
    background: #f7fafc;
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
    .finding__meta,
    .summary-grid--csharp,
    .summary-grid--metrics,
    .section-card-grid {{
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
        <p class="hero__subtitle">{project_path or 'Proyecto analizado'} · Reporte de seguridad estática para Python, con salida HTML y JSON alineada al microservicio independiente.</p>

        <div class="chip-row">
            <span class="chip">Tool: {tool_name}</span>
            <span class="chip">Version: {version}</span>
            <span class="chip">Environment: {environment}</span>
            <span class="chip">Scan: {scan_id}</span>
        </div>

        <div class="hero-grid">
            <div class="risk-card risk-{risk_level.lower()}">
                <span>Nivel de riesgo</span>
                <strong>{self._esc(risk_level)}</strong>
            </div>
            <div class="metric-card">
                <span>Total hallazgos</span>
                <strong>{total_findings}</strong>
                <small>{severity.get("CRITICAL", 0)} critical, {severity.get("HIGH", 0)} high</small>
            </div>
            <div class="metric-card">
                <span>Archivos escaneados</span>
                <strong>{total_files}</strong>
                <small>Generated at {generated_at}</small>
            </div>
        </div>

        <div class="hero-footer">
            <span>Análisis IA: {counts["AI"]}</span>
            <span>Reglas generadas: {counts["Rules"]}</span>
            <span>Reglas coincidentes: {counts["Matches"]}</span>
        </div>
    </section>

    <div class="top-controls">
        <button class="control-btn" id="theme-toggle" type="button">Toggle theme</button>
        <button class="control-btn control-btn--ghost" id="print-report" type="button">Print / PDF</button>
    </div>

    <section class="panel">
        <div class="panel__header">
            <div>
                <h2>Resumen ejecutivo</h2>
                <p>Visión rápida del alcance, el riesgo y la reducción de falsos positivos.</p>
            </div>
        </div>
        <div class="stats-grid summary-grid--csharp">
            <div class="stat"><span>Vulnerabilidades</span><strong>{total_findings}</strong></div>
            <div class="stat"><span>Archivos</span><strong>{total_files}</strong></div>
            <div class="stat"><span>Métodos</span><strong>{methods_count}</strong></div>
            <div class="stat"><span>Clases</span><strong>{classes_count}</strong></div>
            <div class="stat"><span>FP removidos</span><strong>{false_positives_removed}</strong><small>{false_positive_rate}</small></div>
            <div class="stat"><span>Frameworks</span><strong>{frameworks_text}</strong></div>
        </div>
    </section>

    <section class="panel">
        <div class="panel__header">
            <div>
                <h2>Hallazgos</h2>
                <p>Filtra por severidad o busca texto dentro del reporte.</p>
            </div>
        </div>
        <div class="toolbar">
            <input id="search-input" type="search" placeholder="Buscar hallazgos, fuente, sink o vulnerabilidad..." />
        </div>
        <div class="filter-row">
            <button class="filter-chip active" data-filter="ALL" type="button">Todos</button>
            <button class="filter-chip" data-filter="CRITICAL" type="button">Críticas</button>
            <button class="filter-chip" data-filter="HIGH" type="button">Altas</button>
            <button class="filter-chip" data-filter="MEDIUM" type="button">Medias</button>
            <button class="filter-chip" data-filter="LOW" type="button">Bajas</button>
        </div>
        <div class="finding-list" id="finding-list">
            {findings_html}
        </div>
    </section>

    <section class="panel">
        <div class="panel__header">
            <div>
                <h2>Métricas del análisis</h2>
                <p>Indicadores de ejecución y cobertura del pipeline.</p>
            </div>
        </div>
        <div class="mini-grid mini-grid--dense">
            <div class="mini-kpi">
                <span>Archivos</span>
                <strong>{analysis_metrics["files_scanned"]}</strong>
            </div>
            <div class="mini-kpi">
                <span>Métodos</span>
                <strong>{methods_count}</strong>
            </div>
            <div class="mini-kpi">
                <span>Nodos</span>
                <strong>{analysis_metrics["nodes"]}</strong>
            </div>
            <div class="mini-kpi">
                <span>Sources</span>
                <strong>{analysis_metrics["sources"]}</strong>
            </div>
            <div class="mini-kpi">
                <span>Sinks</span>
                <strong>{analysis_metrics["sinks"]}</strong>
            </div>
            <div class="mini-kpi">
                <span>Sanitizers</span>
                <strong>{analysis_metrics["sanitizers"]}</strong>
            </div>
            <div class="mini-kpi">
                <span>Taint paths</span>
                <strong>{analysis_metrics["taint_paths"]}</strong>
            </div>
            <div class="mini-kpi">
                <span>Reglas</span>
                <strong>{len(generated_rules)}</strong>
            </div>
        </div>
        {ai_html}
    </section>

    <section class="panel">
        <div class="panel__header">
            <div>
                <h2>Contexto y remediación</h2>
                <p>Arquitectura observada, archivos más afectados y sugerencias base.</p>
            </div>
        </div>
        <div class="section-card-grid">
            <div class="section-card">
                <h3>Top archivos</h3>
                <p>{top_files_html}</p>
            </div>
            <div class="section-card">
                <h3>Top tipos</h3>
                <p>{top_types_html}</p>
            </div>
            <div class="section-card">
                <h3>Frameworks detectados</h3>
                <p>{frameworks_detected_html}</p>
            </div>
            <div class="section-card">
                <h3>Duración total</h3>
                <p>{duration_text}</p>
            </div>
        </div>
        {rules_html}
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

    @staticmethod
    def _count_unique_finding_values(findings: List[Dict], keys: tuple[str, ...]) -> int:
        values = set()
        for finding in findings:
            for key in keys:
                value = finding.get(key)
                if value:
                    values.add(str(value))
                    break
        return len(values)

    @staticmethod
    def _extract_frameworks(findings: List[Dict]) -> List[str]:
        frameworks = []
        for finding in findings:
            framework = finding.get("framework") or finding.get("technology")
            if framework:
                frameworks.append(str(framework))
        return sorted(set(frameworks))

    def _build_analysis_metrics(self, report_data: Dict, findings: List[Dict], graphs: Dict) -> Dict[str, Any]:
        scan_summary = report_data.get("scan_summary", {}) or {}
        stats = report_data.get("statistics", {}) or {}

        graph_nodes = 0
        graph_taint_paths = 0
        for graph in graphs.values():
            if not graph:
                continue
            graph_nodes += int(graph.get("nodes", 0) or 0)
            graph_taint_paths += int(graph.get("paths", 0) or 0)

        sources = sum(1 for finding in findings if finding.get("source"))
        sinks = sum(1 for finding in findings if finding.get("sink") or finding.get("sink_label"))
        sanitizers = sum(1 for finding in findings if finding.get("sanitized") is True)

        return {
            "files_scanned": scan_summary.get(
                "files_scanned",
                len(report_data.get("project", {}).get("scanned_files", [])),
            ),
            "nodes": graph_nodes,
            "sources": sources,
            "sinks": sinks,
            "sanitizers": sanitizers,
            "taint_paths": graph_taint_paths or int(stats.get("total_findings", len(findings))),
        }

    @staticmethod
    def _build_top_files(findings: List[Dict]) -> str:
        counts: Dict[str, int] = {}
        for finding in findings:
            file_name = Path(str(finding.get("file", "unknown"))).name
            counts[file_name] = counts.get(file_name, 0) + 1
        if not counts:
            return "No disponible"
        items = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        return ", ".join(f"{name} ({count})" for name, count in items[:5])

    @staticmethod
    def _build_top_types(stats: Dict) -> str:
        vulnerabilities = stats.get("vulnerabilities", {}) or {}
        if not vulnerabilities:
            return "No disponible"
        items = sorted(vulnerabilities.items(), key=lambda item: (-int(item[1]), item[0]))
        return ", ".join(f"{name} ({count})" for name, count in items[:5])

    @staticmethod
    def _build_frameworks_detected(findings: List[Dict], project: Dict) -> str:
        frameworks = []
        for finding in findings:
            framework = finding.get("framework") or finding.get("technology")
            if framework:
                frameworks.append(str(framework))
        if not frameworks and project.get("framework"):
            frameworks.append(str(project.get("framework")))
        if not frameworks:
            return "No disponible"
        return ", ".join(sorted(set(frameworks)))

    @staticmethod
    def _format_duration(scan_summary: Dict) -> str:
        duration = scan_summary.get("duration_seconds")
        if duration is None:
            duration = scan_summary.get("duration")
        if duration is None:
            return "No disponible"
        try:
            value = float(duration)
        except (TypeError, ValueError):
            return str(duration)
        return f"{value:.2f} s"

    @staticmethod
    def _format_percentage(part: int, total: int) -> str:
        if total <= 0:
            return "0.0%"
        return f"{(part / total) * 100:.1f}%"

    @staticmethod
    def _confidence_band(confidence: float) -> str:
        if confidence >= 0.85:
            return "high"
        if confidence >= 0.65:
            return "medium"
        return "low"

    @staticmethod
    def _finding_title(finding: Dict) -> str:
        vuln_type = str(finding.get("vulnerability") or finding.get("vulnerability_type") or "UNKNOWN")
        sink_label = str(finding.get("sink_label") or finding.get("sink") or "").strip()
        source = str(finding.get("source") or "").strip()
        titles = {
            "SQL_INJECTION": "SQL Injection",
            "COMMAND_INJECTION": "Command Injection",
            "CODE_INJECTION": "Code Injection",
            "XSS": "XSS",
            "PATH_TRAVERSAL": "Path Traversal",
            "SSRF": "SSRF",
            "INSECURE_DESERIALIZATION": "Insecure Deserialization",
            "HARDCODED_SECRET": "Hardcoded Secret",
        }
        base = titles.get(vuln_type, vuln_type.replace("_", " ").title())
        if vuln_type == "SQL_INJECTION" and sink_label:
            return f"{base} — flujo hacia {sink_label}"
        if vuln_type == "XSS" and sink_label:
            return f"{base} — salida no confiable hacia {sink_label}"
        if vuln_type == "PATH_TRAVERSAL" and source:
            return f"{base} — acceso desde {source}"
        if vuln_type == "SSRF" and sink_label:
            return f"{base} — solicitud a {sink_label}"
        if vuln_type == "HARDCODED_SECRET":
            return f"{base} — secreto expuesto en código"
        return base

    @staticmethod
    def _cwe_text(cwe_id: str, vuln_type: str) -> str:
        descriptions = {
            "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command",
            "CWE-79": "Improper Neutralization of Input During Web Page Generation",
            "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory",
            "CWE-78": "Improper Neutralization of Special Elements used in an OS Command",
            "CWE-94": "Improper Control of Generation of Code",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-918": "Server-Side Request Forgery",
        }
        cwe = cwe_id or "CWE-0"
        return f"{cwe} {descriptions.get(cwe, vuln_type.replace('_', ' ').title())}"

    @staticmethod
    def _reference_links(vuln_type: str, cwe_id: str) -> List[tuple[str, str]]:
        mapping = {
            "SQL_INJECTION": [
                ("OWASP SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
                ("Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
            ],
            "XSS": [
                ("OWASP XSS", "https://owasp.org/www-community/attacks/xss/"),
            ],
            "PATH_TRAVERSAL": [
                ("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
            ],
            "SSRF": [
                ("OWASP SSRF", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
            ],
            "COMMAND_INJECTION": [
                ("OWASP Command Injection", "https://owasp.org/www-community/attacks/Command_Injection"),
            ],
            "HARDCODED_SECRET": [
                ("OWASP Secrets Management", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"),
            ],
            "INSECURE_DESERIALIZATION": [
                ("OWASP Deserialization", "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"),
            ],
        }
        if vuln_type in mapping:
            return mapping[vuln_type]
        if cwe_id == "CWE-89":
            return mapping["SQL_INJECTION"]
        return []

    @staticmethod
    def _extract_method_label(finding: Dict) -> str:
        for key in ("method", "method_name", "function", "function_name", "callee"):
            value = finding.get(key)
            if value:
                return str(value)
        return "No disponible"

    @staticmethod
    def _extract_framework_label(finding: Dict) -> str:
        value = finding.get("framework") or finding.get("technology")
        if value:
            return str(value)
        return "No disponible"

    @staticmethod
    def _finding_line_range(finding: Dict) -> tuple[Any, Any]:
        start = finding.get("source_location")
        end = finding.get("sink_location") or finding.get("line")
        if start is None and end is None:
            end = finding.get("line")
        if start is None:
            start = end
        if end is None:
            end = start
        return start, end

    @staticmethod
    def _format_line_range(start: Any, end: Any) -> str:
        if start is None and end is None:
            return "No disponible"
        if start == end or end is None:
            return f"L{start}"
        return f"L{start} → L{end}"

    @staticmethod
    def _format_location(value: Any) -> str:
        if value in (None, "", 0):
            return ""
        return f"L{value}"

    def _build_findings(self, findings: List[Dict]) -> str:
        if not findings:
            return '<div class="empty">No se detectaron vulnerabilidades.</div>'

        blocks: List[str] = []
        for idx, finding in enumerate(findings, start=1):
            severity = self._normalize_severity_label(finding.get("severity", "LOW"))
            vuln_type = str(finding.get("vulnerability") or finding.get("vulnerability_type", "UNKNOWN"))
            vuln_label = self._esc(vuln_type)
            cwe_id = str(finding.get("cwe_id") or finding.get("cwe") or "CWE-0")
            cwe_text = self._esc(self._cwe_text(cwe_id, vuln_type))
            description = self._esc(finding.get("description", "No description"))
            short_title = self._esc(self._finding_title(finding))
            file_name = self._esc(Path(str(finding.get("file", "unknown"))).name)
            start_line, end_line = self._finding_line_range(finding)
            line_label = self._esc(self._format_line_range(start_line, end_line))
            source = self._esc(finding.get("source", "unknown"))
            sink = self._esc(finding.get("sink_label") or finding.get("sink", "unknown"))
            confidence = float(finding.get("confidence", 0) or 0)
            confidence_label = self._confidence_band(confidence)
            confidence_text = self._esc(f"{confidence:.2f}")
            risk_label = self._esc(confidence_label.lower())
            analysis_type = self._esc(
                finding.get("analysis_type")
                or finding.get("metadata", {}).get("analysis_type")
                or "taint_analysis"
            )
            method = self._esc(self._extract_method_label(finding))
            framework = self._esc(self._extract_framework_label(finding))
            vuln_id = self._esc(
                finding.get("vuln_id")
                or finding.get("finding_id")
                or finding.get("id")
                or "No disponible"
            )
            code_snippet = finding.get("code_snippet", "")
            code_context = finding.get("code_context", []) or []
            path = finding.get("path") or finding.get("taint_path") or []
            path_html = self._esc(" -> ".join(map(str, path))) if path else ""
            code_html = self._render_code_context(code_context, code_snippet)
            references = self._reference_links(vuln_type, cwe_id)
            references_html = ""
            if references:
                references_html = "<ul class=\"references-list\">" + "".join(
                    f"<li><a href=\"{self._esc(url)}\" target=\"_blank\" rel=\"noopener noreferrer\">{self._esc(label)}</a></li>"
                    for label, url in references
                ) + "</ul>"

            source_location = self._format_location(finding.get("source_location"))
            sink_location = self._format_location(finding.get("sink_location") or finding.get("line"))
            context_summary = finding.get("context") or (
                f"Flujo de datos desde {source} hacia {sink}."
                if source != "unknown" or sink != "unknown"
                else "No hay contexto adicional disponible."
            )
            context_summary = self._esc(context_summary)
            recommendation = self._esc(finding.get("recommendation", ""))
            source_block = self._esc(
                f"{source} {source_location}".strip()
                if source_location
                else source
            )
            sink_block = self._esc(
                f"{sink} {sink_location}".strip()
                if sink_location
                else sink
            )

            blocks.append(
                f"""
<article class="finding" data-finding-card data-severity="{severity}">
    <div class="finding__top">
        <div>
            <p class="finding__title">#{idx} {short_title}</p>
            <p class="finding__desc">{vuln_label} · {cwe_text}</p>
            <p class="finding__meta-line">{severity} {confidence_label.lower()} {analysis_type}</p>
        </div>
        <span class="badge {severity.lower()}">{severity}</span>
    </div>

    <div class="finding__summary">
        Archivo: {file_name} &nbsp; Líneas: {line_label} &nbsp; Método: {method} &nbsp; Framework: {framework} &nbsp; Vuln ID: {vuln_id}
    </div>

    <div class="section-block">
        <h3>Descripción</h3>
        <p>{description}</p>
    </div>

    <div class="section-block">
        <h3>Contexto</h3>
        <p>{context_summary}</p>
        {f'<p class="finding__lede"><strong>Path de taint:</strong> {path_html}</p>' if path_html else ''}
    </div>

    <div class="section-block">
        <h3>Contexto de código</h3>
        {code_html if code_html else '<div class="empty">Sin snippet disponible.</div>'}
    </div>

    <div class="section-card-grid">
        <div class="section-card">
            <h3>Fuente</h3>
            <p>{source_block}</p>
        </div>
        <div class="section-card">
            <h3>Sink</h3>
            <p>{sink_block}</p>
        </div>
    </div>

    <div class="section-block">
        <h3>Remediación</h3>
        <p>{recommendation or 'No disponible'}</p>
    </div>

    <div class="section-block">
        <h3>Referencias</h3>
        {references_html if references_html else '<p>No disponible</p>'}
    </div>
</article>"""
            )

        return "\n".join(blocks)

    def _build_ai_analysis(self, ai_analysis: List[Dict]) -> str:
        if not ai_analysis:
            return '<div class="empty">No se generó análisis IA para este escaneo.</div>'

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
            return '<div class="empty">No se generaron reglas en este escaneo.</div>'

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
            return '<div class="empty">No hay resumen de grafos disponible.</div>'

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

    def _render_code_context(self, code_context: List[Dict], code_snippet: str) -> str:
        if code_context:
            lines = []
            for item in code_context:
                line_number = self._esc(item.get("line_number", "?"))
                content = self._esc(item.get("content", ""))
                marker = ">>" if item.get("is_target") else "  "
                lines.append(f"{marker} {line_number:>4} | {content}")
            return f'<pre class="code">{"\n".join(lines)}</pre>'

        if code_snippet:
            return f'<pre class="code">{self._esc(code_snippet)}</pre>'

        return ""

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
<p>Total hallazgos: {total}</p>
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
