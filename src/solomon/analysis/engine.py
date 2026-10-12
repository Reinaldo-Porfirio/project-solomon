from typing import Any

from solomon.core.evidence import Evidence
from solomon.core.findings import Finding
from solomon.core.scoring import HealthScore

from .correlation import CorrelationEngine
from .health import HealthEngine
from .risk import RiskEngine
from .rules import RuleEngine, RuleRegistry

# Ensure rules are registered


class AnalysisResult:
    def __init__(
        self, findings: list[Finding], health: HealthScore, correlation_results: list[Any]
    ):
        self.findings = findings
        self.health = health
        self.correlation_results = correlation_results


class AnalysisEngine:
    """
    Main orchestration engine for Security Audit pipeline.
    """

    def __init__(self, platform: str):
        self.platform = platform

        # Load rules strictly applicable to the platform
        applicable_rules = RuleRegistry.get_for_platform(platform)

        self.rule_engine = RuleEngine(applicable_rules)
        self.correlation_engine = CorrelationEngine()
        self.risk_engine = RiskEngine()
        self.health_engine = HealthEngine()

    def run(self, evidence: list[Evidence]) -> AnalysisResult:
        # 1. Rule Evaluation -> Match generation
        matches = self.rule_engine.evaluate(evidence)

        # 2. Evidence Correlation -> Finding generation
        correlation_results = self.correlation_engine.correlate(matches, evidence)

        findings = []
        for cr in correlation_results:
            if cr.triggered and cr.finding:
                # 3. Explainability mapping
                cr.finding.reasoning += (
                    f" Matched required conditions: {', '.join(cr.matched_conditions)}."
                )
                findings.append(cr.finding)

        # 4. Risk Calculation
        self.risk_engine.attach_risk(findings)

        # 5. Security Health
        health = self.health_engine.calculate(findings)

        return AnalysisResult(
            findings=findings, health=health, correlation_results=correlation_results
        )
