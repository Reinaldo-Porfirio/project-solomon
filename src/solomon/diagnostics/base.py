import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime

from solomon.core.evidence import Evidence

from .status import CollectionResult


class DiagnosticCollector(ABC):
    """
    Base class for specific diagnostic collectors.
    """

    def __init__(self, platform: str):
        self.platform = platform
        self.module_name = self.__class__.__name__.replace("Collector", "").lower()

    @abstractmethod
    def collect(self) -> CollectionResult:
        """Execute collection and return a CollectionResult."""
        pass

    def _create_evidence(
        self,
        category: str,
        component: str,
        observation: str,
        raw_data: dict,
        confidence: float = 1.0,
        collection_method: str = "psutil",
    ) -> Evidence:
        """Helper to create deterministic evidence records."""
        return Evidence(
            evidence_id=f"EV-DIAG-{uuid.uuid4().hex[:8].upper()}",
            source=self.module_name,
            category=category,
            asset="localhost",
            component=component,
            observation=observation,
            raw_data=raw_data,
            confidence=confidence,
            platform=self.platform,
            collection_method=collection_method,
            timestamp=datetime.now(UTC).isoformat(),
        )
