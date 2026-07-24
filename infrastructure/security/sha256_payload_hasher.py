from __future__ import annotations

import hashlib
import json
from typing import Any


class Sha256PayloadHasher:
    def hash(
        self,
        payload: dict[str, Any],
    ) -> str:
        serialized_payload = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        return hashlib.sha256(
            serialized_payload
        ).hexdigest()