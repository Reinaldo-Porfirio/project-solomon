from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """
    Immutable representation of an observed fact.
    Must not depend on OS-specific or collection-specific libraries.
    """

    evidence_id: str
    source: str
    category: str
    asset: str
    component: str
    observation: str
    raw_data: Any
    confidence: float
    platform: str
    collection_method: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
