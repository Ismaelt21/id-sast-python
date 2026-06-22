from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class HardcodedSecretFinding:
    vulnerability: str
    severity: str
    confidence: float
    source: str
    sink: str
    sink_label: str
    source_location: Optional[int]
    sink_location: Optional[int]
    line: Optional[int]
    path: List[str]
    sanitized: bool
    reachable: bool
    description: str
    recommendation: str
    metadata: Dict[str, Any]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "sink": self.sink,
            "sink_label": self.sink_label,
            "source_location": self.source_location,
            "sink_location": self.sink_location,
            "line": self.line,
            "path": self.path,
            "sanitized": self.sanitized,
            "reachable": self.reachable,
            "description": self.description,
            "recommendation": self.recommendation,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


class HardcodedSecretAnalyzer:
    """
    Detecta secretos, passwords y credenciales embebidas en
    el código fuente.
    """

    SENSITIVE_NAME_PATTERN = re.compile(
        r"(api[_-]?key|access[_-]?key|secret|token|password|passphrase|passwd|"
        r"jwt[_-]?secret|refresh[_-]?secret|client[_-]?secret|private[_-]?key|"
        r"master[_-]?key|auth[_-]?token|credential|db[_-]?password|smtp[_-]?password|"
        r"encryption[_-]?key|webhook[_-]?key)",
        re.IGNORECASE,
    )

    SECRET_LITERAL_PATTERN = re.compile(
        r"(AKIA|ASIA|AIza|sk-|ghp_|gho_|ghu_|ghs_|ghr_|xoxb-|xoxa_|whsec_|SG\.)",
        re.IGNORECASE,
    )

    SENSITIVE_CALL_HINTS = {
        "jwt.encode",
        "jwt.decode",
        "openai.OpenAI",
        "boto3.client",
        "paramiko.SSHClient.connect",
        "psycopg2.connect",
        "pymysql.connect",
        "ldap3.Connection",
    }

    def analyze(self, code: str, file_path: str = "<memory>") -> List[Dict[str, Any]]:
        tree = ast.parse(code, filename=file_path)
        findings: List[Dict[str, Any]] = []
        seen: set[Tuple[int, str, str]] = set()

        def add_finding(
            *,
            kind: str,
            name: str,
            literal: str,
            line: int,
            confidence: float,
        ) -> None:
            key = (line, name, literal)
            if key in seen:
                return
            seen.add(key)

            finding = HardcodedSecretFinding(
                vulnerability="HARDCODED_SECRET",
                severity="HIGH",
                confidence=confidence,
                source=name,
                sink="hardcoded_literal",
                sink_label="HARDCODED_SECRET",
                source_location=line,
                sink_location=line,
                line=line,
                path=[name, f"literal@{line}"],
                sanitized=False,
                reachable=True,
                description=(
                    f"Detected hardcoded secret in '{name}' "
                    f"from {kind}."
                ),
                recommendation=(
                    "Use environment variables or a secrets manager."
                ),
                metadata={
                    "detected_by": "hardcoded_secret_analyzer",
                    "analysis_type": "static",
                    "kind": kind,
                    "file": file_path,
                },
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            findings.append(finding.to_dict())

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    target_name = self._get_target_name(target)
                    if not target_name:
                        continue
                    self._scan_value(
                        node.value,
                        target_name,
                        node.lineno,
                        add_finding,
                        context="assignment",
                    )

            elif isinstance(node, ast.AnnAssign):
                target_name = self._get_target_name(node.target)
                if target_name and node.value is not None:
                    self._scan_value(
                        node.value,
                        target_name,
                        node.lineno,
                        add_finding,
                        context="assignment",
                    )

            elif isinstance(node, ast.Call):
                call_name = self._call_name(node)
                if not call_name:
                    continue

                for keyword in node.keywords:
                    if keyword.arg:
                        self._scan_value(
                            keyword.value,
                            keyword.arg,
                            getattr(keyword.value, "lineno", node.lineno),
                            add_finding,
                            context=call_name,
                            force_sensitive=self._is_sensitive_name(keyword.arg)
                            or call_name in self.SENSITIVE_CALL_HINTS,
                        )

                for arg in node.args:
                    self._scan_value(
                        arg,
                        call_name,
                        getattr(arg, "lineno", node.lineno),
                        add_finding,
                        context=call_name,
                        force_sensitive=call_name in self.SENSITIVE_CALL_HINTS,
                    )

            elif isinstance(node, ast.Compare):
                self._scan_compare(node, add_finding)

        return findings

    def _scan_compare(self, node: ast.Compare, add_finding) -> None:
        left_name = self._extract_name(node.left)
        left_literal = self._extract_literal(node.left)

        if left_name and self._is_sensitive_name(left_name):
            if left_literal and self._looks_like_secret_literal(left_literal):
                add_finding(
                    kind="comparison",
                    name=left_name,
                    literal=left_literal,
                    line=getattr(node, "lineno", 0),
                    confidence=0.85,
                )

        for comparator in node.comparators:
            comp_name = self._extract_name(comparator)
            comp_literal = self._extract_literal(comparator)

            if comp_name and self._is_sensitive_name(comp_name):
                if left_literal and self._looks_like_secret_literal(left_literal):
                    add_finding(
                        kind="comparison",
                        name=comp_name,
                        literal=left_literal,
                        line=getattr(node, "lineno", 0),
                        confidence=0.85,
                    )

            if left_name and self._is_sensitive_name(left_name):
                if comp_literal and self._looks_like_secret_literal(comp_literal):
                    add_finding(
                        kind="comparison",
                        name=left_name,
                        literal=comp_literal,
                        line=getattr(node, "lineno", 0),
                        confidence=0.85,
                    )

    def _scan_value(
        self,
        node: ast.AST,
        context_name: str,
        line: int,
        add_finding,
        context: str,
        force_sensitive: bool = False,
    ) -> None:
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, (str, bytes)):
                literal = value.decode() if isinstance(value, bytes) else value
                if force_sensitive or self._is_sensitive_name(context_name):
                    if literal and self._looks_like_secret_literal(literal):
                        add_finding(
                            kind=context,
                            name=context_name,
                            literal=literal,
                            line=getattr(node, "lineno", line),
                            confidence=0.95,
                        )
                elif self._looks_like_secret_literal(literal):
                    add_finding(
                        kind=context,
                        name=context_name,
                        literal=literal,
                        line=getattr(node, "lineno", line),
                        confidence=0.9,
                    )

        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                key_name = self._extract_literal(key) or self._extract_name(key)
                if key_name and self._is_sensitive_name(key_name):
                    self._scan_value(
                        value,
                        key_name,
                        getattr(value, "lineno", line),
                        add_finding,
                        context=f"{context}.dict",
                        force_sensitive=True,
                    )
                else:
                    self._scan_value(
                        value,
                        context_name,
                        getattr(value, "lineno", line),
                        add_finding,
                        context=f"{context}.dict",
                        force_sensitive=force_sensitive,
                    )

        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for item in node.elts:
                self._scan_value(
                    item,
                    context_name,
                    getattr(item, "lineno", line),
                    add_finding,
                    context=context,
                    force_sensitive=force_sensitive,
                )

        elif isinstance(node, ast.Call):
            call_name = self._call_name(node) or context_name
            for keyword in node.keywords:
                if keyword.arg:
                    self._scan_value(
                        keyword.value,
                        keyword.arg,
                        getattr(keyword.value, "lineno", line),
                        add_finding,
                        context=call_name,
                        force_sensitive=force_sensitive
                        or self._is_sensitive_name(keyword.arg)
                        or call_name in self.SENSITIVE_CALL_HINTS,
                    )
            for arg in node.args:
                self._scan_value(
                    arg,
                    call_name,
                    getattr(arg, "lineno", line),
                    add_finding,
                    context=call_name,
                    force_sensitive=force_sensitive or call_name in self.SENSITIVE_CALL_HINTS,
                )

        elif isinstance(node, ast.BinOp):
            self._scan_value(
                node.left,
                context_name,
                getattr(node.left, "lineno", line),
                add_finding,
                context=context,
                force_sensitive=force_sensitive,
            )
            self._scan_value(
                node.right,
                context_name,
                getattr(node.right, "lineno", line),
                add_finding,
                context=context,
                force_sensitive=force_sensitive,
            )

    def _get_target_name(self, target: ast.AST) -> Optional[str]:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return self._attribute_name(target)
        return None

    def _attribute_name(self, node: ast.Attribute) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def _call_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._attribute_name(node.func)
        return None

    def _extract_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._attribute_name(node)
        return None

    def _extract_literal(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            return node.value.decode() if isinstance(node.value, bytes) else node.value
        return None

    def _is_sensitive_name(self, name: str) -> bool:
        return bool(name and self.SENSITIVE_NAME_PATTERN.search(name))

    def _looks_like_secret_literal(self, value: str) -> bool:
        if not value:
            return False

        lower = value.lower()

        # Evitamos confundir plantillas HTML normales con secretos.
        if re.search(r"</?[a-zA-Z][^>]*>", value):
            if not self.SECRET_LITERAL_PATTERN.search(value) and "@" not in value:
                return False

        if re.match(r"^https?://", lower):
            authority = value.split("://", 1)[1].split("/", 1)[0]
            if "@" not in authority:
                return False

        if self.SECRET_LITERAL_PATTERN.search(value):
            return True

        if lower in {"secret", "password", "token", "apikey", "api_key"}:
            return True

        if len(value) >= 16 and any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value):
            return True

        return False
