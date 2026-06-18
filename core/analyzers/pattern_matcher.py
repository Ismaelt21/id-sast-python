from difflib import SequenceMatcher


class PatternMatcher:
    """
    Compara findings del Taint Analysis
    contra patrones vulnerables almacenados.
    """

    MATCH_THRESHOLD = 0.75

    def __init__(self, findings, rules):

        self.findings = findings
        self.rules = rules

        # Corrección #3: inicializados aquí y reseteados en
        # cada llamada a match() para evitar acumulación entre
        # invocaciones sobre la misma instancia.
        self.matches = []
        self.unknown_patterns = []

    # =========================================================
    # MAIN
    # =========================================================

    def match(self):

        # Corrección #3: reset explícito entre llamadas.
        self.matches = []
        self.unknown_patterns = []

        for finding in self.findings:

            matched = False

            for rule in self.rules:

                similarity = self._calculate_similarity(
                    finding,
                    rule,
                )

                if similarity >= self.MATCH_THRESHOLD:

                    self.matches.append({
                        "matched":       True,
                        "rule_id":       rule["rule_id"],
                        # Soportamos ambos formatos de regla
                        "vulnerability": (
                            rule.get("vulnerability_type")
                            or rule.get("vulnerability", "UNKNOWN")
                        ),
                        "similarity":    round(similarity, 2),
                        "finding":       finding,
                    })

                    matched = True

            if not matched:

                self.unknown_patterns.append({
                    "matched":              False,
                    "finding":              finding,
                    "requires_ai_analysis": True,
                })

        return {
            "matches":          self.matches,
            "unknown_patterns": self.unknown_patterns,
        }

    # =========================================================
    # SIMILARITY ENGINE
    # =========================================================

    def _calculate_similarity(self, finding, rule):

        score = 0.0

        # -------------------------------------------------
        # Vulnerability type match
        # Soportamos dos formatos de regla:
        # - built_in_rules.to_dict() → 'vulnerability_type'
        # - MongoDB rules            → 'vulnerability'
        # -------------------------------------------------

        rule_vuln = (
            rule.get("vulnerability_type")
            or rule.get("vulnerability", "")
        )

        if finding.get("vulnerability") == rule_vuln:
            score += 0.4

        # -------------------------------------------------
        # Source match
        # built_in_rules usa 'sources' (lista)
        # MongoDB rules usa 'pattern.source_type' (string)
        # -------------------------------------------------

        finding_source = finding.get("source", "")

        # Formato built_in_rules: campo 'sources' es lista
        rule_sources = rule.get("sources", [])
        # Formato MongoDB: campo 'pattern.source_type'
        pattern = rule.get("pattern", {})
        rule_source_str = pattern.get("source_type", "")

        if rule_sources:
            # Match contra cualquier source de la lista
            if any(
                s.lower() in finding_source.lower()
                for s in rule_sources
            ):
                score += 0.2
        elif rule_source_str:
            if rule_source_str.lower() in finding_source.lower():
                score += 0.2

        # -------------------------------------------------
        # Sink match
        # built_in_rules usa 'sinks' (lista de labels limpios)
        # MongoDB rules usa 'pattern.sink_type' (categoría)
        # -------------------------------------------------

        finding_sink = (
            finding.get("sink_label")
            or finding.get("sink", "")
        )

        rule_sinks = rule.get("sinks", [])
        rule_sink_str = pattern.get("sink_type", "")

        if rule_sinks:
            # Match exacto contra la lista de sinks
            if finding_sink in rule_sinks:
                score += 0.3
        elif rule_sink_str:
            if self._sink_matches(finding_sink, rule_sink_str):
                score += 0.3

        # -------------------------------------------------
        # Propagation match
        # Corrección #1: campo correcto es 'path', no 'taint_path'.
        # -------------------------------------------------

        path_length = len(finding.get("path", []))

        # built_in_rules: 'required_edges' implica propagación
        # MongoDB rules: 'pattern.requires_propagation'
        requires_propagation = (
            pattern.get("requires_propagation", False)
            or len(rule.get("required_edges", [])) > 1
        )

        if requires_propagation and path_length >= 3:
            score += 0.1

        return min(score, 1.0)

        # =========================================================
    # SINK NORMALIZATION
    # Corrección #2: el match ahora se hace sobre el label
    # limpio del sink (ej: "os.system"), no sobre el ID con
    # @lineno (ej: "os.system@5"), eliminando el substring
    # match frágil que producía falsos positivos.
    # =========================================================

    def _sink_matches(self, finding_sink: str, rule_sink: str) -> bool:

        sink_aliases = {
            "SQL_EXECUTION": {
                "cursor.execute",
                "execute",
                "executemany",
            },
            "COMMAND_EXECUTION": {
                "os.system",
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.call",
            },
            "CODE_EXECUTION": {
                "eval",
                "exec",
            },
        }

        aliases = sink_aliases.get(rule_sink, set())

        # Comparación exacta contra el label limpio del sink.
        return finding_sink in aliases


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    import json

    findings = [
        {
            # Campos reales del taint_analyzer corregido
            "vulnerability": "SQL_INJECTION",
            "severity":      "CRITICAL",
            "source":        "input",
            "sink":          "cursor.execute@10",
            "sink_label":    "cursor.execute",
            "path": [
                "input",
                "VAR_1",
                "VAR_2",
                "cursor.execute@10",
            ],
            "sanitized":  False,
            "confidence": 0.75,
        }
    ]

    rules = [
        {
            "rule_id":       "RULE_SQLI_001",
            "vulnerability": "SQL_INJECTION",
            "pattern": {
                "source_type":          "input",
                "sink_type":            "SQL_EXECUTION",
                "requires_propagation": True,
            },
        }
    ]

    matcher = PatternMatcher(findings, rules)

    result = matcher.match()

    print(json.dumps(result, indent=2))