from dataclasses import dataclass
from enum import StrEnum

from solomon.core.evidence import Evidence


class CollectionStatus(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    INSUFFICIENT_PRIVILEGES = "INSUFFICIENT_PRIVILEGES"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class CollectionResult:
    """
    Represents the output of a single diagnostic collector.
    """

    module_name: str
    status: CollectionStatus
    evidence: list[Evidence]
    message: str | None = None
