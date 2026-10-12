from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from .evidence import Evidence
from .scoring import RiskScore


class FindingSeverity(Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    REMEDIATED = "REMEDIATED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class Finding:
    finding_id: str
    title: str
    category: str
    severity: FindingSeverity
    confidence: float
    asset: str
    component: str
    description: str
    evidence_ids: list[str]
    evidence: list[Evidence] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    reasoning: str = ""
    recommendation: str = ""
    remediation: str = ""
    priority: int = 0
    status: FindingStatus = FindingStatus.OPEN
    verification: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    impact: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cwe: str | None = None
    classification: str = "configuration"
    limitations: str = ""
    risk_score: RiskScore | None = None
