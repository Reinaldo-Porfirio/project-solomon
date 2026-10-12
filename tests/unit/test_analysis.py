from solomon.analysis.correlation import CorrelationEngine
from solomon.analysis.windows_rules import WinRDP001
from solomon.core.evidence import Evidence
from solomon.core.findings import FindingSeverity


def test_win_rdp_trigger():
    rule = WinRDP001()
    evidence = [
        Evidence(
            evidence_id="ev1",
            source="mock",
            category="os.service",
            asset="localhost",
            component="TermService",
            observation="RDP service",
            raw_data={"State": "Running"},
            confidence=1.0,
            platform="Windows",
            collection_method="mock",
        ),
        Evidence(
            evidence_id="ev2",
            source="mock",
            category="network.socket",
            asset="localhost",
            component="socket",
            observation="TCP 3389",
            raw_data={"status": "LISTEN", "laddr_port": 3389, "laddr_ip": "0.0.0.0", "pid": 123},
            confidence=1.0,
            platform="Windows",
            collection_method="mock",
        ),
        Evidence(
            evidence_id="ev3",
            source="mock",
            category="network.firewall",
            asset="localhost",
            component="fw",
            observation="Firewall disabled",
            raw_data={"profiles": [{"Name": "Domain", "Enabled": 0}]},
            confidence=1.0,
            platform="Windows",
            collection_method="mock",
        ),
    ]
    matches = rule.evaluate(evidence)
    for m in matches:
        m.rule_id = rule.rule_id

    assert len(matches) == 4
    conds = [m.condition_name for m in matches]
    assert "rdp_enabled" in conds
    assert "rdp_listener" in conds
    assert "rdp_external" in conds
    assert "rdp_firewall" in conds

    # Test Correlation
    engine = CorrelationEngine()
    results = engine.correlate(matches, evidence)

    # We should have one triggered finding for WIN-RDP-001
    rdp_res = next(r for r in results if r.rule_id == "WIN-RDP-001")
    assert rdp_res.triggered is True
    assert rdp_res.finding is not None
    assert rdp_res.finding.severity == FindingSeverity.MEDIUM

    # Test Evidence Provenance
    assert set(rdp_res.finding.evidence_ids) == {"ev1", "ev2", "ev3"}


def test_win_rdp_false_positive():
    rule = WinRDP001()
    # Test: port open on localhost only
    evidence = [
        Evidence(
            evidence_id="ev1",
            source="mock",
            category="os.service",
            asset="localhost",
            component="TermService",
            observation="RDP service",
            raw_data={"State": "Running"},
            confidence=1.0,
            platform="Windows",
            collection_method="mock",
        ),
        Evidence(
            evidence_id="ev2",
            source="mock",
            category="network.socket",
            asset="localhost",
            component="socket",
            observation="TCP 3389",
            raw_data={"status": "LISTEN", "laddr_port": 3389, "laddr_ip": "127.0.0.1", "pid": 123},
            confidence=1.0,
            platform="Windows",
            collection_method="mock",
        ),
        Evidence(
            evidence_id="ev3",
            source="mock",
            category="network.firewall",
            asset="localhost",
            component="fw",
            observation="Firewall disabled",
            raw_data={"profiles": [{"Name": "Domain", "Enabled": 0}]},
            confidence=1.0,
            platform="Windows",
            collection_method="mock",
        ),
    ]
    matches = rule.evaluate(evidence)
    for m in matches:
        m.rule_id = rule.rule_id

    engine = CorrelationEngine()
    results = engine.correlate(matches, evidence)
    rdp_res = next(r for r in results if r.rule_id == "WIN-RDP-001")

    # Missing external exposure! Should not trigger.
    assert rdp_res.triggered is False
    assert rdp_res.finding is None
    assert "Listener is bound to a non-loopback address" in rdp_res.missing_conditions
