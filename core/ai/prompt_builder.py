"""
prompt_builder.py

Construcción de prompts para Gemini.

Responsabilidades:
- Construir prompts optimizados
- Reducir tokens innecesarios
- Compactar AST/CFG/DFG
- Generar contexto semántico
- Guiar análisis IA
- Estandarizar respuestas JSON

IMPORTANTE:
Este módulo NO llama a Gemini.
Solo construye prompts.
"""

import json
from typing import Any, Dict, List

from config.settings import Settings


class PromptBuilder:
    """
    Builder de prompts para análisis IA.
    """

    # =========================================================
    # SYSTEM PROMPT
    # =========================================================

    SYSTEM_PROMPT = """
You are an expert cybersecurity AI specialized in:

- Python Static Application Security Testing (SAST)
- Abstract Syntax Trees (AST)
- Control Flow Graphs (CFG)
- Data Flow Graphs (DFG)
- Taint Analysis
- Semantic Vulnerability Detection
- Subgraph Pattern Recognition
- CWE Classification

Your mission is to analyze Python code graphs and determine
whether a real vulnerability exists.

You must perform:

1. SOURCE ANALYSIS
Determine whether data originates from untrusted input:
- request.args / request.args.get
- request.form / request.form.get
- request.json / request.get_json
- request.values / request.headers / request.cookies
- input()
- sys.argv
- os.environ / os.getenv
- external APIs / file uploads / sockets

2. TAINT PROPAGATION
Track how tainted data moves through:
- variables / assignments / function calls
- object attributes / loops / conditions / returns

3. SANITIZATION ANALYSIS
Determine whether the flow is mitigated using:
- parameterized queries / escaping / validation
- type casting / safe APIs / allowlists

4. SINK DETECTION
Identify dangerous sinks:
- os.system / subprocess.run / subprocess.Popen
- eval / exec / pickle.loads / yaml.load
- cursor.execute / cursor.executemany
- render_template_string
- open (file writes with user path)

5. CONTROL FLOW CONTEXT
Use CFG to determine reachability, conditional execution,
dead code, protected paths, and authorization checks.

6. FALSE POSITIVE REDUCTION
DO NOT mark vulnerabilities if sanitization exists,
parameterized queries are used, shell=False is enforced,
or taint never reaches sink.

7. META RULE GENERATION
Generate reusable logical rules from the detected pattern.

IMPORTANT:
Return STRICTLY VALID JSON.
No markdown. No explanations. No extra text.
"""

    # =========================================================
    # PUBLIC API
    # =========================================================

    def build_analysis_prompt(
        self,
        code:          str,
        ast_data:      Dict,
        dfg_data:      Dict,
        cfg_data:      Dict,
        findings:      List[Dict] = None,
        matched_rules: List[Dict] = None,
    ) -> str:
        """
        Construye el prompt principal para Gemini.

        Corrección #6: verifica que el payload total respete
        MAX_PROMPT_CHARS antes de retornar.
        """

        findings      = findings      or []
        matched_rules = matched_rules or []

        compact_ast = self._compact_ast(ast_data)
        compact_dfg = self._compact_dfg(dfg_data)
        compact_cfg = self._compact_cfg(cfg_data)

        payload = {
            "language":      "python",
            "code":          self._truncate(code),
            "ast":           compact_ast,
            "dfg":           compact_dfg,
            "cfg":           compact_cfg,
            "local_findings": findings,
            "matched_rules":  matched_rules,
        }

        instructions = self._build_analysis_instructions()

        prompt = (
            f"Analyze this Python SAST context.\n\n"
            f"{instructions}\n\n"
            f"INPUT:\n"
            f"{json.dumps(payload, indent=2)}\n\n"
            f"RETURN ONLY VALID JSON."
        )

        # Corrección #6: si el prompt completo supera el límite,
        # reducimos progresivamente los campos más grandes.
        return self._enforce_prompt_limit(prompt, payload, instructions)

    # =========================================================
    # INSTRUCTIONS
    # Corrección #7: el JSON de ejemplo usa 'path' en lugar
    # de 'taint_path', consistente con todo el pipeline.
    # =========================================================

    def _build_analysis_instructions(self) -> str:
        """
        Instrucciones específicas para Gemini.
        """

        return """
Tasks:

1. Determine whether a REAL vulnerability exists.
2. Identify: vulnerability type, CWE, severity, confidence, path.
3. Explain taint propagation: SOURCE -> PROPAGATION -> SINK.
4. Determine if sanitization exists.
5. Classify as: TRUE_POSITIVE, FALSE_POSITIVE, SUSPICIOUS, or SAFE.
6. Generate a reusable semantic rule.
7. Generate a minimal vulnerable subgraph.

JSON FORMAT:

{
  "vulnerability_detected": true,
  "classification": "TRUE_POSITIVE",
  "vulnerability_type": "SQL_INJECTION",
  "cwe": "CWE-89",
  "severity": "HIGH",
  "confidence": 0.97,

  "source": "...",
  "sink": "...",
  "sink_label": "...",

  "path": [
    "source_node",
    "intermediate_variable",
    "sink_node"
  ],

  "sanitization_detected": false,

  "reasoning": "...",

  "subgraph_pattern": {
    "nodes": [],
    "edges": []
  },

  "semantic_rule": {
    "pattern_name": "...",
    "logic": "...",
    "risk": "HIGH"
  }
}
"""

    # =========================================================
    # AST COMPACTION
    # Corrección #5: aplicamos límite MAX_SUBGRAPH_NODES a
    # calls y assignments igual que dfg/cfg hacen con sus
    # nodos, evitando que el AST desborde el prompt.
    # =========================================================

    def _compact_ast(self, ast_data: Dict) -> Dict:
        """
        Reduce el AST para ahorrar tokens.

        Corrección #5: todos los campos se limitan a
        MAX_SUBGRAPH_NODES para consistencia con dfg/cfg.
        """

        limit = Settings.MAX_SUBGRAPH_NODES

        return {
            "imports":     ast_data.get("imports",     [])[:limit],
            "functions":   ast_data.get("functions",   [])[:limit],
            "classes":     ast_data.get("classes",     [])[:limit],
            "calls":       ast_data.get("calls",       [])[:limit],
            "assignments": ast_data.get("assignments", [])[:limit],
        }

    # =========================================================
    # DFG COMPACTION
    # =========================================================

    def _compact_dfg(self, dfg_data: Dict) -> Dict:
        """
        Compacta el DFG para el prompt.
        """

        nodes = dfg_data.get("nodes", [])
        edges = dfg_data.get("edges", [])

        limit_nodes = Settings.MAX_SUBGRAPH_NODES
        limit_edges = limit_nodes * 2

        return {
            "nodes_count": len(nodes),
            "edges_count": len(edges),
            "nodes":       nodes[:limit_nodes],
            "edges":       edges[:limit_edges],
        }

    # =========================================================
    # CFG COMPACTION
    # =========================================================

    def _compact_cfg(self, cfg_data: Dict) -> Dict:
        """
        Compacta el CFG para el prompt.
        """

        nodes = cfg_data.get("nodes", [])
        edges = cfg_data.get("edges", [])

        limit_nodes = Settings.MAX_SUBGRAPH_NODES
        limit_edges = limit_nodes * 2

        return {
            "nodes_count": len(nodes),
            "edges_count": len(edges),
            "nodes":       nodes[:limit_nodes],
            "edges":       edges[:limit_edges],
        }

    # =========================================================
    # PROMPT LIMIT ENFORCEMENT
    # Corrección #6: si el prompt total supera MAX_PROMPT_CHARS,
    # reducimos progresivamente ast → dfg → cfg hasta que quepa.
    # =========================================================

    def _enforce_prompt_limit(
        self,
        prompt:       str,
        payload:      Dict,
        instructions: str,
    ) -> str:
        """
        Garantiza que el prompt no supere MAX_PROMPT_CHARS.

        Estrategia de reducción progresiva:
        1. Reducir AST a la mitad.
        2. Reducir DFG a la mitad.
        3. Reducir CFG a la mitad.
        4. Truncar el prompt final si sigue siendo demasiado.
        """

        max_chars = Settings.MAX_PROMPT_CHARS

        if len(prompt) <= max_chars:
            return prompt

        # Reducción progresiva de los campos más grandes.
        for field in ("ast", "dfg", "cfg"):

            section = payload.get(field, {})

            for key in ("nodes", "edges", "calls", "assignments",
                        "imports", "functions", "classes"):

                if key in section and isinstance(section[key], list):
                    section[key] = section[key][: len(section[key]) // 2]

            payload[field] = section

            prompt = (
                f"Analyze this Python SAST context.\n\n"
                f"{instructions}\n\n"
                f"INPUT:\n"
                f"{json.dumps(payload, indent=2)}\n\n"
                f"RETURN ONLY VALID JSON."
            )

            if len(prompt) <= max_chars:
                return prompt

        # Último recurso: truncar el string completo.
        print(
            f"[PromptBuilder] WARNING: prompt truncated to "
            f"{max_chars} chars."
        )

        return prompt[:max_chars] + "\n...[TRUNCATED]\nRETURN ONLY VALID JSON."

    # =========================================================
    # RULE GENERATION PROMPT
    # Corrección #8: validamos tamaño del input antes de
    # incluirlo en el prompt.
    # =========================================================

    def build_rule_generation_prompt(
        self,
        vulnerability_analysis: Dict,
    ) -> str:
        """
        Prompt para generación de reglas reutilizables.
        """

        analysis_str = self._truncate(
            json.dumps(vulnerability_analysis, indent=2)
        )

        return (
            f"Generate a reusable Python SAST rule.\n\n"
            f"ANALYSIS:\n{analysis_str}\n\n"
            f"Requirements:\n"
            f"- Generalize variable names\n"
            f"- Generalize function names\n"
            f"- Keep semantic structure\n"
            f"- Generate reusable detection logic\n"
            f"- Generate minimal vulnerable subgraph\n\n"
            f"Return ONLY JSON:\n\n"
            f"{{\n"
            f'  "pattern_name": "...",\n'
            f'  "vulnerability_type": "...",\n'
            f'  "logic": "...",\n'
            f'  "subgraph": {{"nodes": [], "edges": []}},\n'
            f'  "confidence": 0.95\n'
            f"}}"
        )

    # =========================================================
    # FALSE POSITIVE PROMPT
    # Corrección #8: truncamos finding y code antes de incluir.
    # =========================================================

    def build_false_positive_prompt(
        self,
        finding: Dict,
        code:    str,
    ) -> str:
        """
        Prompt especializado en reducción de falsos positivos.
        """

        finding_str = self._truncate(
            json.dumps(finding, indent=2)
        )

        return (
            f"Determine whether this Python vulnerability "
            f"is a FALSE POSITIVE.\n\n"
            f"Finding:\n{finding_str}\n\n"
            f"Code:\n{self._truncate(code)}\n\n"
            f"Focus on: sanitization, validation, "
            f"parameterized queries, safe APIs, reachability.\n\n"
            f"Return ONLY JSON:\n\n"
            f"{{\n"
            f'  "is_false_positive": false,\n'
            f'  "confidence": 0.93,\n'
            f'  "reason": "..."\n'
            f"}}"
        )

    # =========================================================
    # SUBGRAPH EXTRACTION PROMPT
    # Corrección #8: truncamos graph_data antes de incluir.
    # =========================================================

    def build_subgraph_prompt(
        self,
        graph_data:         Dict,
        vulnerability_type: str,
    ) -> str:
        """
        Prompt para extraer subgrafo vulnerable mínimo.
        """

        graph_str = self._truncate(
            json.dumps(graph_data, indent=2)
        )

        return (
            f"Extract the MINIMAL vulnerable subgraph.\n\n"
            f"Vulnerability: {vulnerability_type}\n\n"
            f"Graph:\n{graph_str}\n\n"
            f"Return ONLY JSON:\n\n"
            f"{{\n"
            f'  "nodes": [],\n'
            f'  "edges": [],\n'
            f'  "pattern_logic": "..."\n'
            f"}}"
        )

    # =========================================================
    # HELPERS
    # =========================================================

    def _truncate(self, text: str) -> str:
        """
        Limita el tamaño de un campo individual al
        MAX_PROMPT_CHARS configurado en Settings.
        """

        max_chars = Settings.MAX_PROMPT_CHARS

        if len(text) <= max_chars:
            return text

        return text[:max_chars] + "\n...[TRUNCATED]..."

    def get_system_prompt(self) -> str:
        """
        Retorna el system prompt.
        """

        return self.SYSTEM_PROMPT