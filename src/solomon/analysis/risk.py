from solomon.core.findings import Finding, FindingSeverity
from solomon.core.scoring import RiskFactor, RiskScore


class RiskEngine:
    """
    Calculates deterministic risk scores for findings.
    Risk = Severity * Exposure * Impact * Confidence
    Normalized to 0-100.
    """

    def __init__(self):
        self.severity_map = {
            FindingSeverity.INFORMATIONAL: 0.0,
            FindingSeverity.LOW: 0.3,
            FindingSeverity.MEDIUM: 0.6,
            FindingSeverity.HIGH: 0.8,
            FindingSeverity.CRITICAL: 1.0,
        }

    def calculate_risk(self, finding: Finding) -> RiskScore:
        sev_factor = self.severity_map.get(finding.severity, 0.5)

        # In a fully fleshed out engine, exposure and impact would be
        # dynamically calculated based on the asset's tags or the specific
        # component matched. For baseline determinism, we use fixed rules.
        exp_factor = 1.0
        if "external" in finding.reasoning.lower() or "remote" in finding.category.lower():
            exp_factor = 1.0
        elif "local" in finding.reasoning.lower():
            exp_factor = 0.5

        imp_factor = sev_factor  # Base impact on severity if no other data

        # Confidence is provided by the finding (correlation engine)
        # Never inflate confidence beyond the collected evidence.
        conf_factor = max(0.0, min(1.0, finding.confidence))

        # Raw calculation
        raw_risk = sev_factor * exp_factor * imp_factor * conf_factor

        # Normalize to 0-100 (Max raw is 1.0 * 1.0 * 1.0 * 1.0 = 1.0)
        final_score = round(raw_risk * 100, 2)
        final_score = max(0.0, min(100.0, final_score))

        factors = [
            RiskFactor("Severity", sev_factor, f"Derived from {finding.severity.value}"),
            RiskFactor("Exposure", exp_factor, "Assumed 1.0 for external/remote, 0.5 for local"),
            RiskFactor("Impact", imp_factor, "Base impact"),
            RiskFactor("Confidence", conf_factor, "Evidence confidence"),
        ]

        return RiskScore(
            score=final_score,
            severity_factor=sev_factor,
            exposure_factor=exp_factor,
            impact_factor=imp_factor,
            confidence_factor=conf_factor,
            factors=factors,
            reasoning=(
                f"({sev_factor} * {exp_factor} * {imp_factor} * {conf_factor}) "
                f"* 100 = {final_score}"
            ),
        )

    def attach_risk(self, findings: list[Finding]):
        for f in findings:
            risk = self.calculate_risk(f)
            f.priority = int(risk.score)
            f.risk_score = risk  # Attach for explainability
