from solomon.core.findings import Finding, FindingSeverity
from solomon.core.scoring import HealthScore


class HealthEngine:
    """
    Calculates overall system health based on finding impacts.
    """

    def __init__(self, weights: dict[str, int] | None = None):
        # Base weights for categories
        self.weights = {
            "Network": 20,
            "Firewall": 20,
            "Services": 15,
            "Accounts": 15,
            "Remote Access": 15,
            "Updates": 15,
        }
        if weights is not None:
            self.weights = dict(weights)

        # Penalty multipliers based on severity
        self.penalty_map = {
            FindingSeverity.INFORMATIONAL: 0,
            FindingSeverity.LOW: 2,
            FindingSeverity.MEDIUM: 5,
            FindingSeverity.HIGH: 10,
            FindingSeverity.CRITICAL: 20,
        }

    def calculate(self, findings: list[Finding]) -> HealthScore:
        # Start at 100 for each category
        scores = {k: 100 for k in self.weights.keys()}
        weights = dict(self.weights)

        for f in findings:
            cat = f.category
            if cat not in scores:
                scores[cat] = 100
                weights[cat] = 10  # Dynamic category fallback

            penalty = self.penalty_map.get(f.severity, 0)
            scores[cat] = max(0, scores[cat] - penalty)

        # Calculate weighted overall score
        total_weight = sum(weights.values())
        weighted_sum = sum(scores[c] * weights.get(c, 10) for c in scores)

        overall = int(weighted_sum / total_weight) if total_weight > 0 else 100

        return HealthScore(
            overall=overall,
            network=scores.get("Network", 100),
            firewall=scores.get("Firewall", 100),
            ssh=scores.get("SSH", 100),
            services=scores.get("Services", 100),
            accounts=scores.get("Accounts", 100),
            updates=scores.get("Updates", 100),
            filesystem=scores.get("Filesystem", 100),
        )
