import json
from unittest.mock import patch

from solomon.diagnostics.status import CollectionStatus
from solomon.platform.linux.ubuntu.providers import LinuxRouteProvider, LinuxServiceProvider
from solomon.platform.windows.providers import WindowsFirewallProvider, WindowsServiceProvider


@patch("solomon.platform.windows.providers.SafeSubprocess.run")
def test_windows_service_provider_success(mock_run):
    mock_run.return_value.success = True
    mock_run.return_value.stdout = json.dumps(
        [{"Name": "WinDefend", "State": "Running"}, {"Name": "wuauserv", "State": "Stopped"}]
    )

    provider = WindowsServiceProvider()
    status, services, method = provider.get_services()

    assert status == CollectionStatus.SUCCESS
    assert len(services) == 2
    assert services[0]["Name"] == "WinDefend"
    assert method == "PowerShell/CIM"


@patch("solomon.platform.windows.providers.SafeSubprocess.run")
def test_windows_firewall_insufficient_privileges(mock_run):
    mock_run.return_value.success = False
    mock_run.return_value.stderr = "Access denied"

    provider = WindowsFirewallProvider()
    status, state, _ = provider.get_firewall_state()

    assert status == CollectionStatus.INSUFFICIENT_PRIVILEGES


@patch("solomon.platform.linux.ubuntu.providers.shutil.which", return_value="/bin/systemctl")
@patch("solomon.platform.linux.ubuntu.providers.SafeSubprocess.run")
def test_linux_service_provider_malformed_json(mock_run, mock_which):
    mock_run.return_value.success = True
    mock_run.return_value.stdout = "INVALID JSON DATA"

    provider = LinuxServiceProvider()
    status, services, _ = provider.get_services()

    assert status == CollectionStatus.FAILED
    assert len(services) == 0


@patch("solomon.platform.linux.ubuntu.providers.shutil.which", return_value=None)
def test_linux_route_provider_missing_ip(mock_which):
    provider = LinuxRouteProvider()
    status, routes, _ = provider.get_routes()

    assert status == CollectionStatus.NOT_AVAILABLE
