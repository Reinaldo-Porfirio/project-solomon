import json
from pathlib import Path

import pytest

from solomon.lab import run_demo
from solomon.reporting import load_report, save_reports

pytestmark = pytest.mark.integration


def test_complete_local_pentest_and_reports(tmp_path: Path):
    result = run_demo(tmp_path)
    assert result["session_status"] == "COMPLETED"
    assert result["security_health"] == 93  # MEDIUM=5, LOW=2; only web category is evaluated.
    assert result["requests_used"] == 4  # HTTP, TCP, and two CORS probes; technology reuses HTTP.
    assert all(status == "SUCCESS" for status in result["status"].values())
    rules = {finding.rules[0] for finding in result["findings"]}
    assert "WEB-CORS-001" in rules
    assert "WEB-COOKIE-002" in rules
    assert not any(finding.component == "port" for finding in result["findings"])
    paths = save_reports(result, tmp_path)
    saved = load_report(paths["json"])
    assert saved["engagement"]["scope"]["included"] == ["127.0.0.1"]
    assert len(saved["evidence"]) == len({ev["evidence_id"] for ev in saved["evidence"]})
    assert "demo-value" not in json.dumps(saved)
    assert "demo-analytics" not in json.dumps(saved)
