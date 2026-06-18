from __future__ import annotations

import copy
import os
from datetime import datetime
from typing import Any, Dict, Optional

from database.mongodb import MongoDB


class ScanRepository:
    """
    Stores scan documents in-memory and optionally in MongoDB.
    """

    def __init__(self, mongodb: Optional[MongoDB] = None) -> None:
        self.mongodb = mongodb
        self.collection_name = os.getenv("MONGODB_SCANS_COLLECTION", "scans")
        self._memory_store: Dict[str, Dict[str, Any]] = {}

    def save_scan(self, scan_document: Dict[str, Any], persist: bool = True) -> str:
        scan_id = scan_document["scan_id"]
        document = copy.deepcopy(scan_document)
        document.setdefault("stored_at", datetime.utcnow())

        self._memory_store[scan_id] = copy.deepcopy(document)

        if persist and self.mongodb:
            if not self.mongodb.connected:
                self.mongodb.connect()

            if self.mongodb.connected:
                collection = self.mongodb.get_collection(self.collection_name)
                collection.replace_one(
                    {"scan_id": scan_id},
                    document,
                    upsert=True,
                )

        return scan_id

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if scan_id in self._memory_store:
            return copy.deepcopy(self._memory_store[scan_id])

        if self.mongodb:
            if not self.mongodb.connected:
                self.mongodb.connect()

            if self.mongodb.connected:
                collection = self.mongodb.get_collection(self.collection_name)
                document = collection.find_one({"scan_id": scan_id}, {"_id": 0})
                if document:
                    self._memory_store[scan_id] = copy.deepcopy(document)
                    return copy.deepcopy(document)

        return None

    def list_scans(self) -> list[Dict[str, Any]]:
        scans = list(self._memory_store.values())
        return [copy.deepcopy(scan) for scan in scans]

