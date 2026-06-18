"""
rule_generator.py

Generador de reglas inteligentes para PY-SAST.

Responsabilidades:
- Convertir findings IA en reglas reutilizables
- Generar subgrafos mínimos vulnerables
- Generalizar patrones
- Reducir overfitting
- Preparar reglas para MongoDB
- Retroalimentar el motor SAST

IMPORTANTE:
Este módulo NO detecta vulnerabilidades.
Solo transforma análisis IA en reglas persistentes.
"""

import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional


class RuleGenerator:
    """
    Generador de reglas semánticas reutilizables.
    """

    # =========================================================
    # SOURCE NORMALIZATION MAP
    # =========================================================

    SOURCE_MAP = {
        "request.args":      "USER_INPUT",
        "request.args.get":  "USER_INPUT",
        "request.form":      "USER_INPUT",
        "request.form.get":  "USER_INPUT",
        "request.json":      "USER_INPUT",
        "request.get_json":  "USER_INPUT",
        "request.GET":       "USER_INPUT",
        "request.POST":      "USER_INPUT",
        "input":             "USER_INPUT",
        "sys.argv":          "USER_INPUT",
        "os.environ":        "ENVIRONMENT_INPUT",
        "os.getenv":         "ENVIRONMENT_INPUT",
        "socket.recv":       "NETWORK_INPUT",
        "request.body":      "RAW_BODY_INPUT",
        "request.data":      "RAW_BODY_INPUT",
    }

    # =========================================================
    # SINK NORMALIZATION MAP
    # Corrección #9: las claves son los labels limpios
    # (sin @lineno), consistentes con el pipeline corregido.
    # =========================================================

    SINK_MAP = {
        "cursor.execute":    "SQL_EXECUTION",
        "cursor.executemany":"SQL_EXECUTION",
        "os.system":         "COMMAND_EXECUTION",
        "subprocess.run":    "COMMAND_EXECUTION",
        "subprocess.Popen":  "COMMAND_EXECUTION",
        "subprocess.call":   "COMMAND_EXECUTION",
        "eval":              "DYNAMIC_EXECUTION",
        "exec":              "DYNAMIC_EXECUTION",
        "pickle.loads":      "UNSAFE_DESERIALIZATION",
        "yaml.load":         "UNSAFE_DESERIALIZATION",
        "open":              "FILE_ACCESS",
        "requests.get":      "OUTBOUND_REQUEST",
        "requests.post":     "OUTBOUND_REQUEST",
    }

    # =========================================================
    # MAIN
    # =========================================================

    def generate_rule(self, analysis: Dict) -> Dict:
        """
        Genera regla reutilizable desde análisis IA.

        Corrección #11: lee 'path' en lugar de 'taint_path',
        consistente con el campo real del pipeline y con el
        JSON que Gemini devuelve tras la corrección #7 del
        prompt_builder.
        """

        vulnerability_type = analysis.get("vulnerability_type", "UNKNOWN")
        semantic_rule      = analysis.get("semantic_rule",      {})
        subgraph_pattern   = analysis.get("subgraph_pattern",   {})
        source             = analysis.get("source",             "unknown")
        sink               = analysis.get("sink",               "unknown")
        sink_label         = analysis.get("sink_label",         "")
        confidence         = float(analysis.get("confidence",   0.0))

        # Corrección #11: campo correcto es 'path'.
        path = analysis.get("path", [])

        sanitization_detected = analysis.get(
            "sanitization_detected", False
        )

        rule = {
            "rule_id": self._generate_rule_id(
                vulnerability_type, source, sink_label or sink
            ),

            "created_at": datetime.utcnow().isoformat(),

            "pattern_name": semantic_rule.get(
                "pattern_name",
                f"{vulnerability_type}_pattern",
            ),

            "vulnerability_type": vulnerability_type,

            "logic": semantic_rule.get("logic", ""),

            "risk": semantic_rule.get("risk", "MEDIUM"),

            "confidence": confidence,

            "source_pattern": self._normalize_source(source),

            # Corrección #9: normalizamos desde sink_label
            # (limpio, sin @lineno). Fallback a sink si no hay.
            "sink_pattern": self._normalize_sink(
                sink_label or sink
            ),

            "taint_signature": self._build_taint_signature(path),

            "subgraph": self._clean_subgraph(subgraph_pattern),

            "metadata": {
                "generated_by":         "gemini",
                "language":             "python",
                "sanitization_detected": sanitization_detected,
                "learning_enabled":     True,
            },
        }

        return rule

    # =========================================================
    # RULE ID
    # Corrección #10: usamos sha256 truncado en lugar de md5,
    # evitando alertas en auditorías de seguridad del propio
    # tool.
    # =========================================================

    def _generate_rule_id(
        self,
        vulnerability_type: str,
        source:             str,
        sink:               str,
    ) -> str:
        """
        Genera ID único para la regla.

        Corrección #10: sha256 truncado en lugar de md5.
        """

        raw    = f"{vulnerability_type}:{source}:{sink}"
        digest = hashlib.sha256(raw.encode()).hexdigest()

        return f"rule_{digest[:16]}"

    # =========================================================
    # NORMALIZE SOURCE
    # =========================================================

    def _normalize_source(self, source: str) -> str:
        """
        Generaliza el source a una categoría semántica.
        """

        if not source:
            return "UNKNOWN_SOURCE"

        # Búsqueda exacta primero.
        if source in self.SOURCE_MAP:
            return self.SOURCE_MAP[source]

        # Búsqueda por substring para variantes no registradas.
        source_lower = source.lower()

        for key, value in self.SOURCE_MAP.items():
            if key in source_lower:
                return value

        return "USER_INPUT"

    # =========================================================
    # NORMALIZE SINK
    # Corrección #9: ahora recibe el label limpio (sin @lineno)
    # gracias a que generate_rule usa sink_label. El replace
    # ya no deja residuos como "SQL_EXECUTION@10".
    # =========================================================

    def _normalize_sink(self, sink_label: str) -> str:
        """
        Generaliza el sink a una categoría semántica.

        Corrección #9: trabaja sobre el label limpio sin
        @lineno, evitando que queden residuos en el valor
        normalizado (ej: "SQL_EXECUTION@10").
        """

        if not sink_label:
            return "UNKNOWN_SINK"

        # Búsqueda exacta primero.
        if sink_label in self.SINK_MAP:
            return self.SINK_MAP[sink_label]

        # Búsqueda por substring para variantes no registradas.
        sink_lower = sink_label.lower()

        for key, value in self.SINK_MAP.items():
            if key in sink_lower:
                return value

        return "UNKNOWN_SINK"

    # =========================================================
    # TAINT SIGNATURE
    # =========================================================

    def _build_taint_signature(self, path: List[str]) -> str:
        """
        Construye firma compacta del path de taint.

        Corrección #11: el parámetro se llama 'path' para
        reflejar el nombre real del campo en el pipeline.
        """

        if not path:
            return "EMPTY_PATH"

        compact = []

        for item in path:

            normalized = str(item).upper()
            normalized = normalized.replace("REQUEST", "SOURCE")
            normalized = normalized.replace("EXECUTE",  "SINK")

            compact.append(normalized)

        return " -> ".join(compact)

    # =========================================================
    # CLEAN SUBGRAPH
    # =========================================================

    def _clean_subgraph(self, subgraph: Dict) -> Dict:
        """
        Limpia y normaliza el subgrafo para persistencia.
        """

        nodes = subgraph.get("nodes", [])
        edges = subgraph.get("edges", [])

        cleaned_nodes = [
            {
                "id":    node.get("id"),
                "type":  node.get("type"),
                "label": node.get("label"),
            }
            for node in nodes
            if node.get("id")
        ]

        cleaned_edges = [
            {
                "source": edge.get("source"),
                "target": edge.get("target"),
                "type":   edge.get("type"),
            }
            for edge in edges
            if edge.get("source") and edge.get("target")
        ]

        return {
            "nodes": cleaned_nodes,
            "edges": cleaned_edges,
        }

    # =========================================================
    # DEDUPLICATION
    # =========================================================

    def generate_rule_signature(self, rule: Dict) -> str:
        """
        Genera firma sha256 para detectar reglas duplicadas.
        """

        raw = (
            f"{rule.get('vulnerability_type')}|"
            f"{rule.get('source_pattern')}|"
            f"{rule.get('sink_pattern')}|"
            f"{rule.get('taint_signature')}"
        )

        return hashlib.sha256(raw.encode()).hexdigest()

    # =========================================================
    # VALIDATION
    # Corrección #12: validamos también los valores de los
    # campos, no solo su presencia.
    # =========================================================

    def validate_rule(self, rule: Dict) -> bool:
        """
        Valida integridad y valores de la regla.

        Corrección #12: además de verificar presencia de
        campos requeridos, valida que confidence esté en
        [0.0, 1.0] y que vulnerability_type no sea vacío,
        evitando que reglas corruptas lleguen al repositorio.
        """

        required = [
            "rule_id",
            "pattern_name",
            "vulnerability_type",
            "logic",
            "subgraph",
        ]

        for field in required:
            if field not in rule:
                return False

        # Validación de valores.
        confidence = rule.get("confidence")

        if not isinstance(confidence, (int, float)):
            return False

        if not (0.0 <= float(confidence) <= 1.0):
            return False

        if not rule.get("vulnerability_type", "").strip():
            return False

        return True

    # =========================================================
    # EXPORT
    # =========================================================

    def export_training_sample(self, rule: Dict) -> Dict:
        """
        Export de la regla como muestra de entrenamiento IA.
        """

        return {
            "input": {
                "source":    rule.get("source_pattern"),
                "sink":      rule.get("sink_pattern"),
                "signature": rule.get("taint_signature"),
            },
            "output": {
                "vulnerability_type": rule.get("vulnerability_type"),
                "risk":               rule.get("risk"),
            },
        }


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    import json

    # Simula output real de Gemini tras las correcciones
    # del prompt_builder (usa 'path' y 'sink_label').
    analysis = {
        "vulnerability_detected": True,
        "classification":         "TRUE_POSITIVE",
        "vulnerability_type":     "COMMAND_INJECTION",
        "cwe":                    "CWE-78",
        "severity":               "CRITICAL",
        "confidence":             0.95,
        "source":                 "input",
        "sink":                   "os.system@5",
        "sink_label":             "os.system",
        "path": [
            "input",
            "user",
            "os.system@5",
        ],
        "sanitization_detected": False,
        "reasoning": "Untrusted input reaches os.system without sanitization.",
        "subgraph_pattern": {
            "nodes": [
                {"id": "input",       "type": "source",   "label": "input"},
                {"id": "user",        "type": "variable", "label": "user"},
                {"id": "os.system@5", "type": "sink",     "label": "os.system"},
            ],
            "edges": [
                {"source": "input", "target": "user",        "type": "taint"},
                {"source": "user",  "target": "os.system@5", "type": "sink_flow"},
            ],
        },
        "semantic_rule": {
            "pattern_name": "command_injection_via_input",
            "logic":        "USER_INPUT -> COMMAND_EXECUTION without shlex.quote",
            "risk":         "CRITICAL",
        },
    }

    generator = RuleGenerator()

    rule = generator.generate_rule(analysis)

    print("=== GENERATED RULE ===")
    print(json.dumps(rule, indent=2))

    print("\n=== VALID ===")
    print(generator.validate_rule(rule))

    print("\n=== SIGNATURE ===")
    print(generator.generate_rule_signature(rule))

    print("\n=== TRAINING SAMPLE ===")
    print(json.dumps(generator.export_training_sample(rule), indent=2))