from unittest.mock import patch

from solomon.core.scope import Asset, AssetType, EngagementPolicy, Scope
from solomon.pentest.models import AuthorizationStatus, Engagement
from solomon.pentest.recon.technology import TechnologyIdentification


def build_engagement():
    return Engagement(
        engagement_id="ENG-1",
        name="Test",
        authorization_status=AuthorizationStatus.ACTIVE,
        scope=Scope(
            engagement_id="ENG-1",
            included=[Asset(AssetType.DOMAIN, "example.com")],
            excluded=[],
            policy=EngagementPolicy(active_testing=True),
        ),
    )


@patch("solomon.pentest.transport.http.HttpTransport.request")
def test_technology_identification_server_header(mock_req):
    eng = build_engagement()
    tech = TechnologyIdentification(eng)

    # Mocking the dictionary returned by HttpTransport.request
    mock_req.return_value = {
        "status": 200,
        "headers": {"Server": "nginx/1.18.0"},
        "final_url": "http://example.com",
    }

    evs = tech.run("example.com")
    assert len(evs) == 2
    assert evs[0].component == "technology"
    assert evs[0].raw_data["value"] == "nginx/1.18.0"


@patch("solomon.pentest.transport.http.HttpTransport.request")
def test_technology_identification_x_powered_by(mock_req):
    eng = build_engagement()
    tech = TechnologyIdentification(eng)

    mock_req.return_value = {
        "status": 200,
        "headers": {"X-Powered-By": "PHP/8.1"},
        "final_url": "http://example.com",
    }

    evs = tech.run("example.com")
    assert len(evs) == 2
    assert "PHP/8.1" in evs[0].observation
