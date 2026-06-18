"""
semantic_analyzer.py

Análisis semántico avanzado para PY-SAST.

Responsabilidades:
- Reducir falsos positivos
- Analizar contexto semántico
- Detectar mitigaciones reales
- Evaluar explotabilidad
- Analizar sanitización
- Preparar contexto para IA
- Decidir cuándo llamar Gemini

Este módulo NO reemplaza:
- taint analysis
- pattern matching

Los complementa.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# =============================================================
# RESULT MODEL
# =============================================================

@dataclass
class SemanticAnalysisResult:

    vulnerability_detected: bool

    exploitability: str
    semantic_confidence: float

    is_false_positive: bool

    mitigation_detected: bool
    mitigation_type: Optional[str]

    contextual_risk: str

    reasoning: str

    requires_ai_validation: bool

    metadata: Dict[str, Any]

    timestamp: str

    # Corrección #6: asdict() genera una copia profunda del
    # dataclass, evitando devolver una referencia mutable al
    # estado interno del objeto como hacía __dict__.
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================
# SEMANTIC ANALYZER
# =============================================================

class SemanticAnalyzer:
    """
    Analizador semántico avanzado.

    Objetivo:
    Analizar el contexto REAL del flujo vulnerable.

    Ejemplo:
    - sanitización real
    - validaciones
    - condiciones
    - restricciones
    - wrappers seguros
    """

    # =========================================================
    # SAFE VALIDATIONS
    # =========================================================

    SAFE_VALIDATIONS = [
        "is_admin",
        "is_authenticated",
        "validate",
        "sanitize",
        "escape",
        "clean",
        "safe_input",
    ]

    # =========================================================
    # KNOWN SANITIZERS
    # Corrección #3: usados para comparación exacta contra el
    # campo 'label' del nodo, no substring sobre el ID.
    # =========================================================

    KNOWN_SANITIZERS = {
        "escape",
        "html.escape",
        "bleach.clean",
        "markupsafe.escape",
        "urllib.parse.quote",
        "shlex.quote",
        "validators.url",
        "secure_filename",
    }

    # =========================================================
    # SAFE WRAPPERS
    # =========================================================

    SAFE_WRAPPERS = {
        "parameterized_query",
        "prepared_statement",
        "safe_execute",
    }

    # =========================================================
    # CONSTRUCTOR
    # =========================================================

    def __init__(self):
        pass

    # =========================================================
    # MAIN ANALYSIS
    # =========================================================

    def analyze(
        self,
        finding: Dict[str, Any],
        ast_data: Dict[str, Any],
        cfg_data: Dict[str, Any],
        dfg_data: Dict[str, Any],
    ) -> SemanticAnalysisResult:
        """
        Ejecuta análisis semántico profundo.
        """

        mitigation_detected, mitigation_type = (
            self.detect_mitigation(finding, dfg_data)
        )

        exploitability = self.evaluate_exploitability(
            finding,
            cfg_data,
            mitigation_detected,
        )

        semantic_confidence = self.calculate_semantic_confidence(
            finding,
            mitigation_detected,
            exploitability,
        )

        contextual_risk = self.calculate_contextual_risk(
            finding,
            mitigation_detected,
            exploitability,
        )

        is_false_positive = self.detect_false_positive(
            mitigation_detected,
            exploitability,
            semantic_confidence,
        )

        reasoning = self.generate_reasoning(
            finding,
            mitigation_detected,
            mitigation_type,
            exploitability,
        )

        requires_ai = self.requires_ai_validation(
            semantic_confidence,
            mitigation_detected,
            exploitability,
        )

        return SemanticAnalysisResult(
            vulnerability_detected=not is_false_positive,

            exploitability=exploitability,
            semantic_confidence=round(semantic_confidence, 2),

            is_false_positive=is_false_positive,

            mitigation_detected=mitigation_detected,
            mitigation_type=mitigation_type,

            contextual_risk=contextual_risk,

            reasoning=reasoning,

            requires_ai_validation=requires_ai,

            metadata={
                "analyzer":      "semantic_analyzer",
                "analysis_type": "semantic",
                "requires_gemini": requires_ai,
            },

            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    # =========================================================
    # MITIGATION DETECTION
    # =========================================================

    def detect_mitigation(
        self,
        finding: Dict[str, Any],
        dfg_data: Dict[str, Any],
    ):
        """
        Detecta mitigaciones reales en el path del finding.

        Corrección #4: primero respeta el campo 'sanitized'
        que ya calculó el taint_analyzer. Solo si no hay señal
        previa baja a inspeccionar el path nodo a nodo.

        Corrección #1: usa el campo 'path' (nombre real que
        exporta taint_analyzer), no 'taint_path'.

        Corrección #3: compara contra el label limpio del nodo
        (vía dfg_data) en lugar de substring sobre el ID.
        """

        # -------------------------------------------------
        # Corrección #4: el taint_analyzer ya calculó esto;
        # si dice sanitized=True lo tomamos directamente.
        # -------------------------------------------------

        if finding.get("sanitized", False):

            # Intentamos identificar qué sanitizador fue
            # inspeccionando el path para dar un tipo preciso.
            sanitizer_type = self._find_sanitizer_in_path(
                finding, dfg_data
            )

            return True, sanitizer_type or "sanitized"

        # -------------------------------------------------
        # Fallback: inspeccionamos el path nodo a nodo para
        # detectar wrappers seguros que el taint no conoce.
        # -------------------------------------------------

        sanitizer_type = self._find_sanitizer_in_path(
            finding, dfg_data
        )

        if sanitizer_type:
            return True, sanitizer_type

        return False, None

    def _find_sanitizer_in_path(
        self,
        finding: Dict[str, Any],
        dfg_data: Dict[str, Any],
    ) -> Optional[str]:
        """
        Busca sanitizadores o wrappers en el path del finding.

        Corrección #1: campo correcto es 'path'.
        Corrección #3: lookup exacto contra label del nodo,
        construido desde dfg_data para tener la info completa.
        """

        # Corrección #1: 'path' es el campo real del finding.
        taint_path = finding.get("path", [])

        # Construimos un mapa id → label desde dfg_data para
        # hacer lookup exacto en lugar de substring.
        label_map = {
            node["id"]: node.get("label", node["id"])
            for node in dfg_data.get("nodes", [])
        }

        for node_id in taint_path:

            # Corrección #3: usamos el label limpio si existe,
            # sino el propio id (puede ser una variable simple).
            label = label_map.get(node_id, node_id)

            if label in self.KNOWN_SANITIZERS:
                return label

            if label in self.SAFE_WRAPPERS:
                return label

        return None

    # =========================================================
    # EXPLOITABILITY
    # =========================================================

    def evaluate_exploitability(
        self,
        finding: Dict[str, Any],
        cfg_data: Dict[str, Any],
        mitigation_detected: bool,
    ) -> str:
        """
        Evalúa explotabilidad del finding.

        Corrección #2: el campo correcto es 'vulnerability',
        no 'vulnerability_type'.
        """

        if mitigation_detected:
            return "LOW"

        if not finding.get("reachable", True):
            return "LOW"

        # Corrección #2: clave correcta según taint_analyzer.
        vulnerability_type = finding.get("vulnerability", "UNKNOWN")

        critical = {
            "SQL_INJECTION",
            "COMMAND_INJECTION",
            "CODE_INJECTION",
        }

        if vulnerability_type in critical:
            return "HIGH"

        return "MEDIUM"

    # =========================================================
    # SEMANTIC CONFIDENCE
    # =========================================================

    def calculate_semantic_confidence(
        self,
        finding: Dict[str, Any],
        mitigation_detected: bool,
        exploitability: str,
    ) -> float:
        """
        Calcula confidence semántico combinando el score base
        del taint_analyzer con ajustes contextuales.
        """

        score = finding.get("confidence", 0.5)

        if mitigation_detected:
            score -= 0.4

        if exploitability == "HIGH":
            score += 0.2

        if exploitability == "LOW":
            score -= 0.2

        return max(0.0, min(score, 1.0))

    # =========================================================
    # CONTEXTUAL RISK
    # =========================================================

    def calculate_contextual_risk(
        self,
        finding: Dict[str, Any],
        mitigation_detected: bool,
        exploitability: str,
    ) -> str:
        """
        Calcula riesgo contextual.
        """

        if mitigation_detected:
            return "LOW"

        if exploitability == "HIGH":
            return "CRITICAL"

        if exploitability == "MEDIUM":
            return "HIGH"

        return "LOW"

    # =========================================================
    # FALSE POSITIVE DETECTION
    # =========================================================

    def detect_false_positive(
        self,
        mitigation_detected: bool,
        exploitability: str,
        semantic_confidence: float,
    ) -> bool:
        """
        Detecta falsos positivos.
        """

        if mitigation_detected:
            return True

        if exploitability == "LOW":
            return True

        if semantic_confidence < 0.35:
            return True

        return False

    # =========================================================
    # REASONING
    # =========================================================

    def generate_reasoning(
        self,
        finding: Dict[str, Any],
        mitigation_detected: bool,
        mitigation_type: Optional[str],
        exploitability: str,
    ) -> str:
        """
        Genera razonamiento semántico legible.

        Corrección #2: usa la clave correcta 'vulnerability'.
        """

        # Corrección #2: clave correcta.
        vulnerability_type = finding.get("vulnerability", "UNKNOWN")

        # Corrección #1: sink_label si existe, sino sink.
        sink = finding.get("sink_label") or finding.get("sink", "unknown")

        if mitigation_detected:
            return (
                f"The detected {vulnerability_type} flow reaching "
                f"'{sink}' appears mitigated by '{mitigation_type}'."
            )

        # Bug real #2: incluimos vulnerability_type en el mensaje
        # para que los tests y el reporting puedan identificar
        # qué tipo de vulnerabilidad se detectó sin mitigación.
        return (
            f"Detected {vulnerability_type}: untrusted data reaches "
            f"dangerous sink '{sink}' without strong mitigation. "
            f"Exploitability classified as {exploitability}."
        )

    # =========================================================
    # AI VALIDATION DECISION
    # Corrección #5: lógica revisada para no enviar a Gemini
    # casos donde ya hay señal clara (mitigación confirmada o
    # exploitabilidad HIGH con alta confianza).
    # =========================================================

    def requires_ai_validation(
        self,
        semantic_confidence: float,
        mitigation_detected: bool,
        exploitability: str,
    ) -> bool:
        """
        Decide si el finding requiere validación por Gemini.

        Criterio: solo enviamos a IA los casos ambiguos donde
        el análisis estático no tiene suficiente señal.

        Corrección #5:
        - Mitigación detectada + confianza alta → NO necesita IA,
          el análisis estático ya lo resolvió.
        - Exploitability HIGH + confianza alta → NO necesita IA,
          es un verdadero positivo claro.
        - Zona gris (confianza media, exploitability MEDIUM,
          mitigación dudosa) → SÍ necesita IA.
        """

        # Caso claro: alta confianza y sin mitigación → TP obvio.
        if exploitability == "HIGH" and semantic_confidence >= 0.65:
            return False

        # Caso claro: mitigación confirmada con confianza muy baja
        # → FP obvio, no necesita IA.
        if mitigation_detected and semantic_confidence <= 0.25:
            return False

        # Bug real #3: confianza baja sin mitigación siempre
        # requiere IA, independientemente de la exploitability.
        # Antes la condición HIGH+alta confianza bloqueaba este
        # caso cuando exploitability era HIGH pero confianza baja.
        if semantic_confidence < 0.50:
            return True

        # Zona gris: exploitability media → IA ayuda a decidir.
        if exploitability == "MEDIUM":
            return True

        # Zona gris: mitigación detectada pero confianza media
        # → puede ser FP o TP con mitigación débil.
        if mitigation_detected and semantic_confidence > 0.25:
            return True

        return False

    # =========================================================
    # BULK ANALYSIS
    # =========================================================

    def analyze_many(
        self,
        findings: List[Dict[str, Any]],
        ast_data: Dict[str, Any],
        cfg_data: Dict[str, Any],
        dfg_data: Dict[str, Any],
    ) -> List[SemanticAnalysisResult]:
        """
        Analiza múltiples findings.
        """

        return [
            self.analyze(finding, ast_data, cfg_data, dfg_data)
            for finding in findings
        ]

    # =========================================================
    # EXPORT
    # =========================================================

    def export_results(
        self,
        results: List[SemanticAnalysisResult],
    ) -> List[Dict[str, Any]]:
        """
        Exporta resultados serializables.
        """

        return [r.to_dict() for r in results]


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    import json

    # Simula output real del taint_analyzer corregido.
    # Campos: 'vulnerability', 'path', 'sink_label', 'sanitized'.

    dfg_data = {
        "nodes": [
            {"id": "input",         "type": "source",   "label": "input"},
            {"id": "user",          "type": "variable", "label": "user"},
            {"id": "query",         "type": "variable", "label": "query"},
            {"id": "os.system@5",   "type": "sink",     "label": "os.system"},
        ],
        "edges": [],
    }

    # ---------------------------------------------------------
    # Caso 1: finding sin sanitizar → vulnerability_detected
    # ---------------------------------------------------------

    finding_unsafe = {
        "vulnerability": "COMMAND_INJECTION",
        "severity":      "CRITICAL",
        "source":        "input",
        "sink":          "os.system@5",
        "sink_label":    "os.system",
        "path":          ["input", "user", "query", "os.system@5"],
        "sanitized":     False,
        "confidence":    0.75,
    }

    # ---------------------------------------------------------
    # Caso 2: finding sanitizado → false positive
    # ---------------------------------------------------------

    finding_safe = {
        "vulnerability": "COMMAND_INJECTION",
        "severity":      "CRITICAL",
        "source":        "input",
        "sink":          "os.system@5",
        "sink_label":    "os.system",
        "path":          ["input", "user", "shlex.quote", "os.system@5"],
        "sanitized":     True,
        "confidence":    0.35,
    }

    analyzer = SemanticAnalyzer()

    for label, finding in [
        ("CASO 1: sin sanitizar",  finding_unsafe),
        ("CASO 2: sanitizado",     finding_safe),
    ]:
        print(f"\n=== {label} ===")
        result = analyzer.analyze(
            finding,
            ast_data={},
            cfg_data={},
            dfg_data=dfg_data,
        )
        print(json.dumps(result.to_dict(), indent=2))