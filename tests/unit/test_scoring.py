import uuid

from solomon.analysis.health import HealthEngine
from solomon.analysis.risk import RiskEngine
from solomon.core.findings import Finding, FindingSeverity


def create_finding(severity, confidence, reasoning="external", category="Network"):
    return Finding(
        finding_id=str(uuid.uuid4()),
        title="Test",
        category=category,
        severity=severity,
        confidence=confidence,
        asset="localhost",
        component="test",
        description="test",
        evidence_ids=[],
        reasoning=reasoning,
    )


def test_risk_engine_bounds():
    engine = RiskEngine()

    # Informational observations never increase vulnerability risk.
    f_min = create_finding(FindingSeverity.INFORMATIONAL, 0.05, reasoning="local")
    r_min = engine.calculate_risk(f_min)
    assert r_min.score == 0

    # Maximum risk: Critical severity (1.0), external (1.0), high conf (1.0)
    f_max = create_finding(FindingSeverity.CRITICAL, 1.0, reasoning="external")
    r_max = engine.calculate_risk(f_max)
    assert r_max.score == 100.0


def test_health_engine():
    engine = HealthEngine()

    # Perfect health
    h_perf = engine.calculate([])
    assert h_perf.overall == 100

    # One medium network finding (penalty 5)
    f1 = create_finding(FindingSeverity.MEDIUM, 1.0, category="Network")
    h_med = engine.calculate([f1])
    assert h_med.network == 95
    assert h_med.overall < 100

    # Critical finding drops score heavily
    f2 = create_finding(FindingSeverity.CRITICAL, 1.0, category="Network")
    h_crit = engine.calculate([f1, f2])
    assert h_crit.network == 75  # 100 - 5 - 20
