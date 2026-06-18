from datetime import datetime
from typing import List, Optional
import os
import uuid

from database.mongodb import MongoDB


class RuleRepository:
    """
    Repository para gestión de reglas vulnerables.

    Responsabilidades:
    - Guardar reglas
    - Buscar reglas
    - Detectar duplicados
    - Actualizar reglas
    - Obtener estadísticas

    NO maneja:
    - lógica de análisis
    - taint analysis
    - IA
    """

    def __init__(self, mongodb: MongoDB):

        self.mongodb = mongodb

        # Corrección #9: nombre de colección leído desde env
        # en lugar de hardcodeado como string literal.
        self.collection = self.mongodb.get_collection(
            os.getenv("MONGODB_RULES_COLLECTION", "security_rules")
        )

    # =========================================================
    # SAVE
    # =========================================================

    def save_rule(
        self,
        vulnerability:   str,
        pattern:         dict,
        graph_signature: dict,
        confidence:      float,
        created_by:      str = "system",
        validated:       bool = False,
    ) -> str:
        """
        Guarda una nueva regla.

        Corrección #11: valida que confidence esté en [0.0, 1.0]
        antes de persistir para evitar scores corruptos.
        """

        # Corrección #11: validación de confidence.
        if not isinstance(confidence, (int, float)):
            raise ValueError(
                "confidence must be a numeric value."
            )

        confidence = float(confidence)

        if not (0.0 <= confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, "
                f"got {confidence}."
            )

        if not vulnerability or not vulnerability.strip():
            raise ValueError("vulnerability cannot be empty.")

        existing = self.find_similar_rule(
            vulnerability=vulnerability,
            pattern=pattern,
        )

        if existing:
            print("[RuleRepository] Similar rule already exists")
            return existing["rule_id"]

        rule_id = f"RULE_{uuid.uuid4().hex[:12]}"

        now = datetime.utcnow()

        rule_document = {
            "rule_id":         rule_id,
            "vulnerability":   vulnerability.strip(),
            "pattern":         pattern,
            "graph_signature": graph_signature,
            "confidence":      confidence,
            "created_by":      created_by,
            "validated":       validated,
            "created_at":      now,
            "updated_at":      now,
            "version":         "1.0.0",
        }

        self.collection.insert_one(rule_document)

        print(f"[RuleRepository] Rule saved: {rule_id}")

        return rule_id

    # =========================================================
    # GETTERS
    # =========================================================

    def get_all_rules(self) -> List[dict]:
        """
        Retorna todas las reglas.
        """

        return list(self.collection.find({}, {"_id": 0}))

    def get_rule_by_id(self, rule_id: str) -> Optional[dict]:
        """
        Busca regla por ID.
        """

        return self.collection.find_one(
            {"rule_id": rule_id},
            {"_id": 0},
        )

    def get_rules_by_vulnerability(
        self,
        vulnerability: str,
    ) -> List[dict]:
        """
        Busca reglas por tipo de vulnerabilidad.
        """

        return list(
            self.collection.find(
                {"vulnerability": vulnerability},
                {"_id": 0},
            )
        )

    def get_validated_rules(self) -> List[dict]:
        """
        Obtiene reglas validadas manualmente.
        """

        return list(
            self.collection.find({"validated": True}, {"_id": 0})
        )

    def get_unvalidated_rules(self) -> List[dict]:
        """
        Obtiene reglas generadas automáticamente
        aún no validadas.
        """

        return list(
            self.collection.find({"validated": False}, {"_id": 0})
        )

    # =========================================================
    # SIMILARITY
    # Corrección #10: find_similar_rule ahora filtra campos
    # None del pattern antes de construir la query. Si
    # source_type o sink_type son None, no se incluyen en el
    # filtro, evitando que MongoDB los trate como {"$eq": None}
    # y retorne None cuando debería encontrar coincidencias.
    # =========================================================

    def find_similar_rule(
        self,
        vulnerability: str,
        pattern:       dict,
    ) -> Optional[dict]:
        """
        Busca reglas similares para evitar duplicados.

        Corrección #10: solo incluye en el filtro los campos
        del pattern que tienen valor real (no None). Esto
        evita falsos "no encontrado" cuando los campos son
        opcionales.
        """

        query: dict = {"vulnerability": vulnerability}

        source_type = pattern.get("source_type")
        sink_type   = pattern.get("sink_type")

        # Solo filtramos por campos que tienen valor real.
        if source_type is not None:
            query["pattern.source_type"] = source_type

        if sink_type is not None:
            query["pattern.sink_type"] = sink_type

        return self.collection.find_one(query, {"_id": 0})

    # =========================================================
    # UPDATE
    # =========================================================

    def validate_rule(self, rule_id: str) -> bool:
        """
        Marca una regla como validada.
        """

        result = self.collection.update_one(
            {"rule_id": rule_id},
            {
                "$set": {
                    "validated":  True,
                    "updated_at": datetime.utcnow(),
                }
            },
        )

        return result.modified_count > 0

    def update_confidence(
        self,
        rule_id:    str,
        confidence: float,
    ) -> bool:
        """
        Actualiza confidence score de una regla.

        Corrección #11: misma validación que save_rule.
        """

        confidence = float(confidence)

        if not (0.0 <= confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, "
                f"got {confidence}."
            )

        result = self.collection.update_one(
            {"rule_id": rule_id},
            {
                "$set": {
                    "confidence": confidence,
                    "updated_at": datetime.utcnow(),
                }
            },
        )

        return result.modified_count > 0

    # =========================================================
    # DELETE
    # =========================================================

    def delete_rule(self, rule_id: str) -> bool:
        """
        Elimina una regla por ID.
        """

        result = self.collection.delete_one({"rule_id": rule_id})

        return result.deleted_count > 0

    # =========================================================
    # STATISTICS
    # Corrección #12: reemplazamos tres count_documents
    # independientes por un aggregation pipeline que calcula
    # todo en un solo round-trip a MongoDB.
    # =========================================================

    def get_statistics(self) -> dict:
        """
        Estadísticas generales del repositorio de reglas.

        Corrección #12: aggregation pipeline en lugar de tres
        count_documents separados. Un solo round-trip para
        obtener total, validadas y no validadas.
        """

        pipeline = [
            {
                "$group": {
                    "_id":             None,
                    "total":           {"$sum": 1},
                    "validated":       {
                        "$sum": {
                            "$cond": ["$validated", 1, 0]
                        }
                    },
                    "unvalidated":     {
                        "$sum": {
                            "$cond": ["$validated", 0, 1]
                        }
                    },
                }
            }
        ]

        result = list(self.collection.aggregate(pipeline))

        if not result:
            return {
                "total_rules":              0,
                "validated_rules":          0,
                "unvalidated_rules":        0,
                "vulnerability_types":      [],
                "total_vulnerability_types": 0,
            }

        row = result[0]

        # distinct sigue siendo un query separado pero es
        # necesario porque $group no agrupa por vulnerability
        # en el mismo pipeline. Para colecciones grandes se
        # podría extender el pipeline, pero para el volumen
        # esperado de reglas esto es aceptable.
        vulnerabilities = self.collection.distinct("vulnerability")

        return {
            "total_rules":               row.get("total",       0),
            "validated_rules":           row.get("validated",   0),
            "unvalidated_rules":         row.get("unvalidated", 0),
            "vulnerability_types":       vulnerabilities,
            "total_vulnerability_types": len(vulnerabilities),
        }

    # =========================================================
    # EXPORT
    # =========================================================

    def export_rules(self) -> List[dict]:
        """
        Export simplificado de reglas para reporting.
        """

        return [
            {
                "rule_id":         rule["rule_id"],
                "vulnerability":   rule["vulnerability"],
                "source_type":     rule["pattern"].get("source_type"),
                "sink_type":       rule["pattern"].get("sink_type"),
                "transformations": rule["pattern"].get("transformations", []),
                "confidence":      rule["confidence"],
                "validated":       rule["validated"],
                "created_by":      rule["created_by"],
            }
            for rule in self.get_all_rules()
        ]


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    from database.mongodb import MongoDB

    mongo = MongoDB()
    mongo.connect()

    repo = RuleRepository(mongo)

    rule_id = repo.save_rule(
        vulnerability="SQL_INJECTION",
        pattern={
            "source_type":     "input",
            "sink_type":       "cursor.execute",
            "transformations": ["STRING_CONCAT"],
        },
        graph_signature={
            "nodes": 4,
            "edges": 3,
            "path":  ["SOURCE", "PROPAGATION", "SINK"],
        },
        confidence=0.94,
        created_by="gemini",
    )

    print(repo.get_all_rules())
    print(repo.get_statistics())

    mongo.disconnect()