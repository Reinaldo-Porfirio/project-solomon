import asyncio
import json
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import pytest

from solomon.analysis.engine import AnalysisEngine
from solomon.analysis.health import HealthEngine
from solomon.core.evidence import Evidence
from solomon.pentest.engagement import new_engagement
from solomon.pentest.engine import PentestDiscoveryEngine
from solomon.pentest.security import PentestRuleEngine
from solomon.pentest.transport.base import TransportTimeoutError
from solomon.reporting import load_report, prepare_report, report_evidence, save_reports
from solomon.tui.app import SolomonConsole


def sample(asset="https://example.test/"):
    return Evidence(
        "ev1",
        "mock",
        "pentest",
        asset,
        "http",
        "Observed",
        {
            "status": 200,
            "headers": {"Set-Cookie": "sessionid=secret", "Server": "<script>alert(1)</script>"},
            "content_type": "text/html",
            "final_url": asset,
            "cookies": [{"name": "sessionid", "secure": False, "httponly": False, "samesite": ""}],
        },
        0.9,
        "Network",
        "mock",
        "2026-01-01T00:00:00+00:00",
    )


def result():
    evidence = [sample("https://example.test/?token=secret")]
    engagement = new_engagement("Laboratório", ["example.test"], [], True, "Meu laboratório", True)
    from solomon.pentest.engagement import engagement_dict

    return {
        "schema_version": 1,
        "session_id": "SESS-TEST",
        "kind": "pentest",
        "session_status": "COMPLETED",
        "target": evidence[0].asset,
        "status": {"HTTP": "SUCCESS"},
        "checks": [],
        "evidence": evidence,
        "findings": PentestRuleEngine().analyze(evidence),
        "security_health": 99,
        "engagement": engagement_dict(engagement),
        "limitations": [],
    }


def test_exports_are_redacted_escaped_and_keep_authorization_snapshot(tmp_path):
    paths = save_reports(result(), tmp_path)
    report = load_report(paths["json"])
    assert report["session_id"] == "SESS-TEST"
    assert report["engagement"]["authorization_status"] == "ACTIVE"
    assert report["engagement"]["authorization_reference"] == "Meu laboratório"
    for path in paths.values():
        assert "token=secret" not in path.read_text(encoding="utf-8")
        assert "sessionid=secret" not in path.read_text(encoding="utf-8")
    rendered = paths["html"].read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "default-src 'none'" in rendered
    assert len(report["evidence"][0]["sha256"]) == 64
    assert report["evidence"][0]["raw_data"]["cookies"][0]["name"] == "sessionid"
    assert report["findings"][0]["evidence"][0]["sha256"] == report["evidence"][0]["sha256"]
    assert len(report_evidence(report)) == 1


def test_modified_evidence_rejected(tmp_path):
    path = save_reports(result(), tmp_path)["json"]
    data = json.loads(path.read_text(encoding="utf-8"))
    data["evidence"][0]["observation"] = "altered"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="Hash"):
        load_report(path)


def test_report_path_cannot_escape_output(tmp_path):
    data = result()
    data["session_id"] = "../../outside"
    with pytest.raises(ValueError):
        save_reports(data, tmp_path)


def test_offline_reanalysis_preserves_findings_after_secret_redaction():
    report = prepare_report(result())
    previous = report["findings"]
    regenerated = [asdict(f) for f in PentestRuleEngine().analyze(report_evidence(report))]
    assert {f["finding_id"] for f in previous} == {f["finding_id"] for f in regenerated}


@patch("solomon.pentest.transport.http.HttpTransport.request")
@patch("solomon.pentest.transport.dns.DnsTransport.resolve")
def test_engine_does_not_run_unselected_modules(mock_dns, mock_http):
    eng = new_engagement("Lab", ["https://example.test/path"], [], True, "Lab")
    mock_http.return_value = {
        "status": 200,
        "final_url": "https://example.test/path",
        "content_type": "application/json",
        "headers": {},
        "cookies": [],
    }
    engine = PentestDiscoveryEngine(eng)
    report = engine.run("https://example.test/path", ["HTTP", "TECHNOLOGY", "HTTP"])
    assert mock_http.call_count == 1
    mock_dns.assert_not_called()
    assert set(report["status"]) == {"HTTP", "TECHNOLOGY"}
    assert report["session_status"] == "COMPLETED"


@patch(
    "solomon.pentest.transport.http.HttpTransport.request",
    side_effect=TransportTimeoutError("timeout"),
)
def test_inconclusive_session_does_not_claim_security_health_100(mock_http):
    eng = new_engagement("Lab", ["example.test"], [], True, "Lab")
    report = PentestDiscoveryEngine(eng).run("https://example.test/", ["HTTP"])
    assert report["session_status"] == "FAILED"
    assert report["status"]["HTTP"] == "INCONCLUSIVE"
    assert report["security_health"] is None
    assert report["findings"] == []


def test_audit_rules_loaded_in_normal_execution_and_findings_are_deterministic():
    firewall = Evidence(
        "fw",
        "mock",
        "network.firewall",
        "localhost",
        "Windows Defender Firewall",
        "Disabled",
        {"profiles": [{"Name": "Private", "Enabled": False}]},
        0.7,
        "Windows",
        "mock",
    )
    first = AnalysisEngine("Windows 11").run([firewall])
    second = AnalysisEngine("Windows 11").run([firewall])
    assert len(first.findings) == 1
    assert first.findings == second.findings
    assert first.findings[0].confidence == 0.7
    assert first.findings[0].recommendation
    assert first.findings[0].evidence[0] == firewall


def test_health_engine_does_not_retain_previous_category_state():
    finding = PentestRuleEngine().analyze([sample()])[0]
    engine = HealthEngine()
    original = engine.calculate([]).overall
    engine.calculate([finding])
    assert engine.calculate([]).overall == original == 100


@patch("solomon.pentest.transport.tcp.TcpTransport.connect")
def test_port_only_session_has_no_vulnerabilities_or_security_score(mock_tcp):
    eng = new_engagement("Lab", ["127.0.0.1"], [], True, "Lab", True)
    mock_tcp.return_value = {"status": "OPEN", "port": 8000, "target": "127.0.0.1"}
    report = PentestDiscoveryEngine(eng).run("127.0.0.1", ["PORTS"], [8000])
    assert report["session_status"] == "COMPLETED"
    assert report["findings"] == []
    assert report["security_health"] is None


def test_tui_starts_without_remote_network_calls():
    async def run():
        detector = MagicMock()
        detector.detect.return_value.platform = "Windows test"
        detector.detect.return_value.privilege_level.value = "STANDARD_USER"
        with (
            patch("solomon.tui.app.get_platform_detector", return_value=detector),
            patch("solomon.tui.app.DiagnosticsEngine.run", return_value={}),
            patch("solomon.pentest.transport.http.HttpTransport.request") as http,
            patch("solomon.pentest.transport.tls.TlsTransport.inspect_tls") as tls,
            patch("solomon.pentest.transport.dns.DnsTransport.resolve") as dns,
            patch("solomon.pentest.transport.tcp.TcpTransport.connect") as tcp,
        ):
            app = SolomonConsole()
            async with app.run_test(size=(120, 44)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                http.assert_not_called()
                tls.assert_not_called()
                dns.assert_not_called()
                tcp.assert_not_called()
                assert "Nenhuma coleta remota" in str(app.query_one("#pentest-state").content)

    asyncio.run(run())
