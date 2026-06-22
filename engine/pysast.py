from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.settings import Settings
from core.ai.rule_generator import RuleGenerator
from core.analyzers.pattern_matcher import PatternMatcher
from core.analyzers.hardcoded_secret_analyzer import HardcodedSecretAnalyzer
from core.analyzers.semantic_analyzer import SemanticAnalyzer
from core.analyzers.taint_analyzer import TaintAnalyzer
from core.analyzers.vulnerability_classifier import VulnerabilityClassifier
from core.parsers.ast_parser import ASTParser
from core.parsers.cfg_builder import CFGBuilder
from core.parsers.dfg_builder import DFGBuilder
from core.parsers.normalizer import ASTNormalizer
from core.rules.built_in_rules import get_all_rules
from database.analysis_repository import AnalysisRepository
from database.mongodb import MongoDB
from database.rule_repository import RuleRepository
from reports.console_report import ConsoleReport
from reports.html_report import HTMLReport
from reports.json_report import JSONReport


class PySAST:
    """
    Main scan engine for Python projects.
    """

    def __init__(
        self,
        use_ai: bool = True,
        verbose: bool = False,
        json_only: bool = False,
        html_only: bool = False,
    ):
        self.use_ai = use_ai and Settings.USE_GEMINI
        self.verbose = verbose
        self.json_only = json_only
        self.html_only = html_only

        self.ast_parser = ASTParser()
        self.normalizer = ASTNormalizer()
        self.cfg_builder = CFGBuilder()
        self.dfg_builder = DFGBuilder()
        self.secret_analyzer = HardcodedSecretAnalyzer()
        self.semantic_analyzer = SemanticAnalyzer()
        self.vulnerability_classifier = VulnerabilityClassifier()
        self.rule_generator = RuleGenerator()

        self.json_report = JSONReport()
        self.console_report = ConsoleReport()
        self.html_report = HTMLReport()

    def scan_project(self, project_path: str) -> Dict[str, Any]:
        project_root = Path(project_path).resolve()
        scanned_files = self._find_python_files(str(project_root))

        findings: List[Dict[str, Any]] = []
        ai_analysis_results: List[Dict[str, Any]] = []
        generated_rules: List[Dict[str, Any]] = []

        mongo: Optional[MongoDB] = None
        rule_repository: Optional[RuleRepository] = None
        analysis_repository: Optional[AnalysisRepository] = None

        if Settings.USE_PERSISTENCE:
            mongo = MongoDB()
            if mongo.connect():
                rule_repository = RuleRepository(mongo)
                analysis_repository = AnalysisRepository(mongo)
            else:
                mongo = None

        for file_path in scanned_files:
            try:
                if os.path.getsize(file_path) > Settings.MAX_FILE_SIZE:
                    continue

                code = Path(file_path).read_text(encoding="utf-8")
                if not code.strip():
                    continue

                ast_data = self.ast_parser.parse(code, file_path)
                normalized_ast = self.normalizer.normalize(ast_data)
                cfg_data = self.cfg_builder.build(normalized_ast) if Settings.ENABLE_CFG else {}
                dfg_data = self.dfg_builder.build_from_code(code) if Settings.ENABLE_DFG else {
                    "nodes": [],
                    "edges": [],
                    "tainted_variables": [],
                }

                hardcoded_findings: List[Dict[str, Any]] = self.secret_analyzer.analyze(
                    code,
                    file_path,
                )

                taint_findings: List[Dict[str, Any]] = []
                if Settings.ENABLE_TAINT_ANALYSIS and dfg_data["nodes"]:
                    taint_findings = TaintAnalyzer(dfg_data).analyze()

                matched_rules: Dict[str, Any] = {"matches": [], "unknown_patterns": []}
                if taint_findings:
                    rules_for_matcher = [rule.to_dict() for rule in get_all_rules()]
                    matched_rules = PatternMatcher(taint_findings, rules_for_matcher).match()

                semantic_results: List[Dict[str, Any]] = []
                if Settings.ENABLE_SEMANTIC_ANALYSIS and taint_findings:
                    raw_semantic = self.semantic_analyzer.analyze_many(
                        findings=taint_findings,
                        ast_data=normalized_ast,
                        cfg_data=cfg_data,
                        dfg_data=dfg_data,
                    )
                    semantic_results = self.semantic_analyzer.export_results(raw_semantic)
                    ai_analysis_results.extend(semantic_results)

                classified_findings: List[Dict[str, Any]] = []
                for raw_finding in hardcoded_findings + taint_findings:
                    classified = self.vulnerability_classifier.classify(raw_finding).to_dict()
                    classified["file"] = file_path
                    classified_findings.append(classified)

                findings.extend(classified_findings)

                if Settings.ENABLE_RULE_GENERATION and taint_findings:
                    for taint_finding in taint_findings:
                        rule = self.rule_generator.generate_rule(taint_finding)
                        if not self.rule_generator.validate_rule(rule):
                            continue
                        generated_rules.append(rule)
                        if rule_repository:
                            try:
                                rule_repository.save_rule(
                                    vulnerability=rule.get("vulnerability_type", "UNKNOWN"),
                                    pattern={
                                        "source_type": rule.get("source_pattern"),
                                        "sink_type": rule.get("sink_pattern"),
                                        "transformations": [],
                                    },
                                    graph_signature=rule.get("subgraph", {}),
                                    confidence=rule.get("confidence", 0.0),
                                    created_by="gemini",
                                )
                            except Exception:
                                pass

                if analysis_repository and classified_findings:
                    try:
                        analysis_repository.save_analysis(
                            project_name=project_root.name,
                            scanned_files=1,
                            vulnerabilities=classified_findings,
                            metadata={
                                "file": file_path,
                                "matched_rules": matched_rules,
                                "semantic_count": len(semantic_results),
                            },
                        )
                    except Exception:
                        pass

            except Exception as exc:
                if self.verbose or Settings.DEBUG:
                    print(f"[ERROR] {file_path}: {exc}")

        report = self.json_report.generate(
            project_name=project_root.name,
            scanned_files=scanned_files,
            findings=findings,
            ai_analysis=ai_analysis_results,
            generated_rules=generated_rules,
        )

        report_paths = {"json": None, "html": None}
        if not self.html_only:
            try:
                report_paths["json"] = self.json_report.save(report)
            except Exception as exc:
                if self.verbose or Settings.DEBUG:
                    print(f"[WARNING] Could not save JSON report: {exc}")

        if not self.json_only:
            try:
                report_paths["html"] = self.html_report.generate(report)
            except Exception as exc:
                if self.verbose or Settings.DEBUG:
                    print(f"[WARNING] Could not save HTML report: {exc}")

        if not self.json_only and not self.html_only:
            self.console_report.generate(
                project_name=project_root.name,
                scanned_files=scanned_files,
                findings=findings,
            )

        if mongo:
            mongo.disconnect()

        report["reports"] = report_paths
        report["scan_summary"] = {
            "project_name": project_root.name,
            "files_scanned": len(scanned_files),
            "findings_count": len(findings),
            "generated_rules": len(generated_rules),
        }

        return report

    def _find_python_files(self, project_path: str) -> List[str]:
        python_files: List[str] = []

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [directory for directory in dirs if directory not in Settings.BLOCKED_DIRECTORIES]

            for file in files:
                if not any(file.endswith(ext) for ext in Settings.ALLOWED_EXTENSIONS):
                    continue
                python_files.append(os.path.join(root, file))

        return python_files
