from unittest.mock import patch

from solomon.core.scope import Asset, AssetType
from solomon.pentest.scope_matcher import ScopeMatcher


def test_domain_matching():
    asset = Asset(AssetType.DOMAIN, "example.com")
    assert ScopeMatcher.match_asset("example.com", asset) is True
    assert ScopeMatcher.match_asset("Example.COM", asset) is True
    assert ScopeMatcher.match_asset("sub.example.com", asset) is False
    assert ScopeMatcher.match_asset("notexample.com", asset) is False


def test_wildcard_matching():
    asset = Asset(AssetType.WILDCARD_DOMAIN, "*.example.com")
    assert ScopeMatcher.match_asset("api.example.com", asset) is True
    assert ScopeMatcher.match_asset("www.example.com", asset) is True
    assert ScopeMatcher.match_asset("deep.api.example.com", asset) is True

    # Apex should fail per requirement
    assert ScopeMatcher.match_asset("example.com", asset) is False

    # Suffix injections should fail
    assert ScopeMatcher.match_asset("evil-example.com", asset) is False
    assert ScopeMatcher.match_asset("example.com.evil.com", asset) is False


def test_url_matching():
    # Asset is URL - strict match
    asset_url = Asset(AssetType.URL, "https://example.com/app")
    assert ScopeMatcher.match_asset("https://example.com/app", asset_url) is True
    assert ScopeMatcher.match_asset("https://example.com/api", asset_url) is False

    # Target is URL against DOMAIN scope
    asset_domain = Asset(AssetType.DOMAIN, "example.com")
    assert ScopeMatcher.match_asset("https://example.com:8443/path", asset_domain) is True
    assert (
        ScopeMatcher.match_asset("http://api.example.com/test", asset_domain) is False
    )  # Subdomain


def test_ip_cidr_matching():
    asset_ipv4 = Asset(AssetType.IPV4, "192.168.1.10")
    assert ScopeMatcher.match_asset("192.168.1.10", asset_ipv4) is True
    assert ScopeMatcher.match_asset("192.168.1.11", asset_ipv4) is False

    asset_cidr = Asset(AssetType.CIDR, "192.168.1.0/24")
    assert ScopeMatcher.match_asset("192.168.1.10", asset_cidr) is True
    assert ScopeMatcher.match_asset("192.168.2.10", asset_cidr) is False

    asset_ipv6 = Asset(AssetType.IPV6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert ScopeMatcher.match_asset("2001:db8:85a3::8a2e:370:7334", asset_ipv6) is True


@patch("socket.gethostbyname")
@patch("socket.socket")
def test_zero_network_execution(mock_socket, mock_dns):
    asset = Asset(AssetType.DOMAIN, "example.com")
    ScopeMatcher.match_asset("api.example.com", asset)
    ScopeMatcher.match_asset("https://example.com", asset)

    # Ensure network calls were absolutely never made during scope resolution
    mock_socket.assert_not_called()
    mock_dns.assert_not_called()
