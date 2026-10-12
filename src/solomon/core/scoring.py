from dataclasses import dataclass


@dataclass
class RiskFactor:
    name: str
    value: float
    description: str


@dataclass
class RiskScore:
    """
    Deterministic risk score calculated from severity, exposure, impact, and confidence.
    """

    score: float
    severity_factor: float
    exposure_factor: float
    impact_factor: float
    confidence_factor: float
    factors: list[RiskFactor]
    reasoning: str

    @property
    def level(self) -> str:
        if self.score < 20:
            return "INFORMATIONAL"
        if self.score < 40:
            return "LOW"
        if self.score < 60:
            return "MEDIUM"
        if self.score < 80:
            return "HIGH"
        return "CRITICAL"


@dataclass
class HealthScore:
    """
    High-level system security score.
    """

    overall: int
    network: int
    firewall: int
    ssh: int
    services: int
    accounts: int
    updates: int
    filesystem: int
