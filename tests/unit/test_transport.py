from unittest.mock import MagicMock, patch
from urllib.request import Request

import pytest

from solomon.core.scope import Asset, AssetType, EngagementPolicy, Scope
from solomon.pentest.models import AuthorizationStatus, Engagement
from solomon.pentest.transport.base import TargetBlockedError
from solomon.pentest.transport.dns import DnsTransport
from solomon.pentest.transport.http import HttpTransport


def build_engagement():
    return Engagement(
        engagement_id="ENG-1",
        name="Test",
        authorization_status=AuthorizationStatus.ACTIVE,
        scope=Scope(
            engagement_id="ENG-1",
            included=[Asset(AssetType.DOMAIN, "example.com")],
            excluded=[Asset(AssetType.HOSTNAME, "admin.example.com")],
            policy=EngagementPolicy(active_testing=True),
        ),
    )


@patch("urllib.request.OpenerDirector.open")
def test_http_transport_allowed(mock_open):
    eng = build_engagement()
    trans = HttpTransport(eng)

    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.geturl.return_value = "http://example.com"
    mock_resp.info.return_value.items.return_value = [("Server", "nginx")]
    mock_resp.read.return_value = b"OK"
    mock_open.return_value.__enter__.return_value = mock_resp

    res = trans.request("http://example.com")
    assert res["status"] == 200
    assert res["headers"]["Server"] == "nginx"


@patch("urllib.request.OpenerDirector.open")
def test_http_transport_blocked_target(mock_open):
    eng = build_engagement()
    trans = HttpTransport(eng)

    with pytest.raises(TargetBlockedError):
        trans.request("http://admin.example.com")

    mock_open.assert_not_called()


@patch("urllib.request.OpenerDirector.open")
def test_http_transport_blocked_redirect(mock_open):
    eng = build_engagement()

    # We want to mock a redirect loop to admin.example.com that should be trapped
    # However, since OpenerDirector handles redirects internally based on the HTTPRedirectHandler
    # intercepting it directly in the handler is what we want.

    # Let's test the GuardedRedirectHandler explicitly.
    from solomon.pentest.transport.http import GuardedRedirectHandler

    handler = GuardedRedirectHandler(eng)

    with pytest.raises(TargetBlockedError):
        handler.redirect_request(
            Request("http://example.com"),
            MagicMock(),
            301,
            "Moved",
            MagicMock(),
            "http://admin.example.com",
        )


@patch("dns.resolver.Resolver.resolve")
def test_dns_transport_allowed(mock_resolve):
    eng = build_engagement()
    trans = DnsTransport(eng)

    mock_answer = MagicMock()
    mock_answer.__str__.return_value = "1.2.3.4"
    # mock iterate
    mock_resolve.return_value = [mock_answer]

    res = trans.resolve("example.com")
    assert res["status"] == "SUCCESS"
    assert "1.2.3.4" in res["records"]


@patch("dns.resolver.Resolver.resolve")
def test_dns_transport_blocked(mock_resolve):
    eng = build_engagement()
    trans = DnsTransport(eng)

    with pytest.raises(TargetBlockedError):
        trans.resolve("admin.example.com")

    mock_resolve.assert_not_called()
