"""Read-only structured PowerShell collectors with explicit UTF-8 output."""

import json
import shutil
from typing import Any

from solomon.diagnostics.status import CollectionStatus
from solomon.platform.base.providers import FirewallProvider, RouteProvider, ServiceProvider
from solomon.platform.base.subprocess import SafeSubprocess


def powershell_command(script: str) -> list[str]:
    executable = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
    prefix = (
        "$ErrorActionPreference='Stop'; "
        "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); "
        "$OutputEncoding=[Console]::OutputEncoding; "
    )
    return [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prefix + script]


def collect_json(script: str, method: str) -> tuple[CollectionStatus, Any, str]:
    result = SafeSubprocess(timeout=30).run(powershell_command(script))
    if not result.success:
        error_message = result.error_message if isinstance(result.error_message, str) else ""
        message = (result.stderr + " " + error_message).lower()
        if any(
            value in message
            for value in (
                "access denied",
                "access is denied",
                "permissiondenied",
                "unauthorizedaccess",
                "acesso negado",
                "acesso é negado",
                "0x80070005",
            )
        ):
            return CollectionStatus.INSUFFICIENT_PRIVILEGES, None, method
        if "Executable not found" in error_message:
            return CollectionStatus.NOT_AVAILABLE, None, method
        return CollectionStatus.FAILED, None, method
    if not result.stdout:
        return CollectionStatus.NOT_AVAILABLE, None, method
    try:
        return CollectionStatus.SUCCESS, json.loads(result.stdout.lstrip("\ufeff")), method
    except json.JSONDecodeError:
        return CollectionStatus.FAILED, None, method


class WindowsServiceProvider(ServiceProvider):
    def get_services(self) -> tuple[CollectionStatus, list[dict[str, Any]], str]:
        status, data, method = collect_json(
            "Get-CimInstance Win32_Service -ErrorAction Stop | "
            "Select-Object Name,DisplayName,State,StartMode,PathName,StartName,ProcessId | "
            "ConvertTo-Json -Compress -Depth 4",
            "PowerShell/CIM",
        )
        if status != CollectionStatus.SUCCESS:
            return status, [], method
        data = [data] if isinstance(data, dict) else data
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            return CollectionStatus.FAILED, [], method
        return status, data, method


class WindowsRouteProvider(RouteProvider):
    def get_routes(self) -> tuple[CollectionStatus, list[dict[str, Any]], str]:
        status, data, method = collect_json(
            "Get-NetRoute -ErrorAction Stop | "
            "Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,"
            "@{Name='AddressFamily';Expression={$_.AddressFamily.ToString()}} | "
            "ConvertTo-Json -Compress -Depth 4",
            "PowerShell/NetRoute",
        )
        if status != CollectionStatus.SUCCESS:
            return status, [], method
        data = [data] if isinstance(data, dict) else data
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            return CollectionStatus.FAILED, [], method
        return status, data, method


class WindowsFirewallProvider(FirewallProvider):
    def get_firewall_state(self) -> tuple[CollectionStatus, dict[str, Any], str]:
        status, data, method = collect_json(
            "Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,"
            "@{Name='Enabled';Expression={$_.Enabled.ToString() -eq 'True'}},"
            "@{Name='DefaultInboundAction';Expression={$_.DefaultInboundAction.ToString()}},"
            "@{Name='DefaultOutboundAction';Expression={$_.DefaultOutboundAction.ToString()}} | "
            "ConvertTo-Json -Compress -Depth 4",
            "PowerShell/NetFirewallProfile",
        )
        if status != CollectionStatus.SUCCESS:
            return status, {}, method
        data = [data] if isinstance(data, dict) else data
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            return CollectionStatus.FAILED, {}, method
        return status, {"profiles": data, "backend": "Windows Defender Firewall"}, method
