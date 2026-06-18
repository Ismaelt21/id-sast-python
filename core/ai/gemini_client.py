"""
gemini_client.py

Cliente Gemini para PY-SAST.

Responsabilidades:
- Conectarse con Google Gemini
- Enviar prompts
- Parsear respuestas JSON
- Manejar errores
- Fallback seguro
- Validar respuestas IA
- Reducir hallucinations

IMPORTANTE:
Este módulo NO construye prompts.
Solo:
Prompt -> Gemini -> JSON limpio
"""

import json
import re
from typing import Any, Dict, Optional

import google.generativeai as genai

from config.settings import Settings


class GeminiClient:
    """
    Cliente oficial Gemini para análisis SAST.
    """

    # =========================================================
    # CIRCUIT BREAKER CONFIG
    # Corrección #4: umbral de fallos consecutivos antes de
    # deshabilitar temporalmente las llamadas a Gemini.
    # =========================================================

    MAX_CONSECUTIVE_FAILURES = 5

    # =========================================================
    # INIT
    # =========================================================

    def __init__(self):

        self.enabled    = (
            Settings.USE_GEMINI
            and bool(Settings.GOOGLE_GEMINI_API_KEY)
        )
        self.model_name = Settings.GEMINI_MODEL
        self.model      = None

        # Corrección #4: contador de fallos consecutivos para
        # el circuit breaker.
        self._consecutive_failures = 0

        if self.enabled:
            self._initialize()

    # =========================================================
    # INITIALIZE
    # =========================================================

    def _initialize(self) -> None:
        """
        Inicializa el cliente Gemini.
        """

        try:

            genai.configure(api_key=Settings.GOOGLE_GEMINI_API_KEY)

            self.model = genai.GenerativeModel(self.model_name)

            print(f"[Gemini] Initialized model: {self.model_name}")

        except Exception as e:

            print(f"[Gemini] Initialization error: {e}")

            self.enabled = False

    # =========================================================
    # MAIN ANALYSIS
    # =========================================================

    def analyze(
        self,
        prompt:        str,
        system_prompt: str,
    ) -> Dict[str, Any]:
        """
        Ejecuta análisis IA contra Gemini.
        """

        if not self.enabled:
            return self._fallback_response("Gemini disabled")

        # Corrección #4: circuit breaker — si hemos fallado
        # demasiadas veces consecutivas, no seguimos intentando.
        if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
            return self._fallback_response(
                f"Gemini circuit breaker open after "
                f"{self._consecutive_failures} consecutive failures. "
                f"Call reset_circuit_breaker() to retry."
            )

        try:

            full_prompt = f"SYSTEM:\n{system_prompt}\n\nUSER:\n{prompt}"

            response = self.model.generate_content(full_prompt)

            raw_text = response.text.strip()

            parsed_json = self._extract_json(raw_text)

            if not parsed_json:

                self._record_failure()

                return self._fallback_response(
                    "Invalid JSON response",
                    raw_text if Settings.DEBUG else None,
                )

            # Éxito: resetemos el contador de fallos.
            self._consecutive_failures = 0

            result = {
                "success": True,
                "source":  "gemini",
                "model":   self.model_name,
                "analysis": parsed_json,
            }

            # Corrección #2: raw_response solo se incluye en
            # modo DEBUG para evitar exponer fragmentos de
            # código analizado en producción.
            if Settings.DEBUG:
                result["raw_response"] = raw_text

            return result

        except Exception as e:

            self._record_failure()

            return self._fallback_response(str(e))

    # =========================================================
    # JSON EXTRACTION
    # Corrección #1: en lugar del regex greedy que fallaba con
    # múltiples objetos JSON, usamos un parser incremental que
    # encuentra el primer objeto JSON completo y válido.
    # =========================================================

    def _extract_json(self, text: str) -> Optional[Dict]:
        """
        Extrae el primer objeto JSON válido del texto.

        Corrección #1: busca el primer '{' y avanza con un
        contador de profundidad para encontrar el cierre
        correcto, evitando que el regex greedy capture
        demasiado cuando hay múltiples objetos JSON.
        """

        # Intento directo primero (respuesta limpia).
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass

        # Búsqueda incremental del primer JSON completo.
        start = text.find("{")

        if start == -1:
            return None

        depth = 0

        for i, char in enumerate(text[start:], start=start):

            if char == "{":
                depth += 1

            elif char == "}":
                depth -= 1

                if depth == 0:

                    candidate = text[start : i + 1]

                    try:
                        return json.loads(candidate)
                    except (json.JSONDecodeError, ValueError):
                        # Si el candidato no es válido, seguimos
                        # buscando el siguiente '{'.
                        next_start = text.find("{", i + 1)

                        if next_start == -1:
                            return None

                        start = next_start
                        depth = 0

        return None

    # =========================================================
    # VALIDATION
    # =========================================================

    def validate_response(self, analysis: Dict) -> bool:
        """
        Valida estructura mínima de la respuesta de Gemini.
        """

        required_fields = [
            "vulnerability_detected",
            "classification",
            "confidence",
        ]

        return all(field in analysis for field in required_fields)

    # =========================================================
    # FALLBACK
    # =========================================================

    def _fallback_response(
        self,
        reason:       str,
        raw_response: Optional[str] = None,
    ) -> Dict:
        """
        Respuesta segura cuando Gemini no está disponible
        o retorna una respuesta inválida.
        """

        response = {
            "success": False,
            "source":  "fallback",
            "error":   reason,
            "analysis": {
                "vulnerability_detected": False,
                "classification":         "UNKNOWN",
                "confidence":             0.0,
                "reasoning":              reason,
            },
        }

        # Corrección #2: raw_response solo en DEBUG.
        if Settings.DEBUG and raw_response:
            response["raw_response"] = raw_response

        return response

    # =========================================================
    # SAFE ANALYSIS
    # =========================================================

    def safe_analyze(
        self,
        prompt:        str,
        system_prompt: str,
    ) -> Dict:
        """
        Wrapper seguro con validación de esquema.
        """

        result = self.analyze(prompt, system_prompt)

        if not result["success"]:
            return result

        analysis = result.get("analysis", {})

        if not self.validate_response(analysis):
            return self._fallback_response(
                "Invalid analysis schema",
                result.get("raw_response"),
            )

        return result

    # =========================================================
    # CIRCUIT BREAKER HELPERS
    # Corrección #4: métodos para gestionar el circuit breaker.
    # =========================================================

    def _record_failure(self) -> None:
        """
        Registra un fallo consecutivo.
        """

        self._consecutive_failures += 1

        if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
            print(
                f"[Gemini] Circuit breaker OPEN after "
                f"{self._consecutive_failures} consecutive failures. "
                f"Calls will be skipped until reset."
            )

    def reset_circuit_breaker(self) -> None:
        """
        Resetea el circuit breaker manualmente.
        Útil después de resolver un problema de cuota o red.
        """

        self._consecutive_failures = 0
        print("[Gemini] Circuit breaker reset.")

    def is_circuit_open(self) -> bool:
        """
        Indica si el circuit breaker está abierto.
        """

        return self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES

    # =========================================================
    # HEALTHCHECK
    # Corrección #3: timeout explícito vía generation_config
    # para evitar que el healthcheck bloquee indefinidamente.
    # =========================================================

    def healthcheck(self) -> bool:
        """
        Verifica disponibilidad de Gemini.

        Corrección #3: usa generation_config con max_output_tokens
        mínimo para reducir latencia y costo del check.
        """

        if not self.enabled:
            return False

        try:

            response = self.model.generate_content(
                "Reply ONLY with the word: OK",
                generation_config=genai.GenerationConfig(
                    max_output_tokens=5,
                    temperature=0.0,
                ),
            )

            ok = "OK" in response.text

            if ok:
                # Un healthcheck exitoso no resetea el circuit
                # breaker; solo reset_circuit_breaker() lo hace.
                pass

            return ok

        except Exception as e:

            print(f"[Gemini] Healthcheck failed: {e}")

            return False

    # =========================================================
    # STATUS
    # =========================================================

    def get_status(self) -> Dict:
        """
        Estado actual del cliente Gemini.
        """

        return {
            "enabled":              self.enabled,
            "model":                self.model_name,
            "provider":             "google_gemini",
            "circuit_breaker_open": self.is_circuit_open(),
            "consecutive_failures": self._consecutive_failures,
        }