import json
import shutil
from typing import Any

from solomon.diagnostics.status import CollectionStatus
from solomon.platform.base.providers import FirewallProvider, RouteProvider, ServiceProvider
from solomon.platform.base.subprocess import SafeSubprocess


class LinuxServiceProvider(ServiceProvider):
    def get_services(self) -> tuple[CollectionStatus, list[dict[str, Any]], str]:
        if not shutil.which("systemctl"):
            return CollectionStatus.NOT_AVAILABLE, [], "systemctl"

        cmd = ["systemctl", "list-units", "--type=service", "--all", "-o", "json"]
        proc = SafeSubprocess()
        res = proc.run(cmd)

        if not res.success:
            return CollectionStatus.FAILED, [], "systemctl"

        try:
            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]
            return CollectionStatus.SUCCESS, data, "systemctl"
        except json.JSONDecodeError:
            return CollectionStatus.FAILED, [], "systemctl"


class LinuxRouteProvider(RouteProvider):
    def get_routes(self) -> tuple[CollectionStatus, list[dict[str, Any]], str]:
        if not shutil.which("ip"):
            return CollectionStatus.NOT_AVAILABLE, [], "ip route"

        cmd = ["ip", "-j", "route"]
        proc = SafeSubprocess()
        res = proc.run(cmd)

        if not res.success:
            return CollectionStatus.FAILED, [], "ip route"

        try:
            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]
            return CollectionStatus.SUCCESS, data, "ip route"
        except json.JSONDecodeError:
            return CollectionStatus.FAILED, [], "ip route"


class LinuxFirewallProvider(FirewallProvider):
    def get_firewall_state(self) -> tuple[CollectionStatus, dict[str, Any], str]:
        # Simple ufw detection for baseline
        if shutil.which("ufw"):
            cmd = ["ufw", "status", "verbose"]
            proc = SafeSubprocess()
            res = proc.run(cmd)

            if not res.success:
                if (
                    "root" in res.stderr.lower()
                    or "permission" in res.stderr.lower()
                    or "must be run as root" in res.stdout.lower()
                ):
                    return CollectionStatus.INSUFFICIENT_PRIVILEGES, {}, "ufw"
                return CollectionStatus.FAILED, {}, "ufw"

            state = {"backend": "ufw", "output": res.stdout}
            return CollectionStatus.SUCCESS, state, "ufw"

        if shutil.which("nft"):
            return (
                CollectionStatus.INSUFFICIENT_PRIVILEGES,
                {"backend": "nftables"},
                "nftables",
            )  # Just placeholder for missing privs since we can't parse easily right now

        return CollectionStatus.NOT_AVAILABLE, {}, "unknown"
