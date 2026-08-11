from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(
    frozen=True,
    slots=True,
)
class URLhausBulkRecord:
    external_record_id: str
    payload: dict[str, object]
    retrieved_at: datetime
    source_url: str