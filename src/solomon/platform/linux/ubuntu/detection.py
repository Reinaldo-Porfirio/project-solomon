import os
import platform
import shutil
from pathlib import Path

from solomon.platform.base.capabilities import PlatformCapabilities, PrivilegeLevel
from solomon.platform.base.detection import PlatformDetector


class UbuntuDetector(PlatformDetector):
    """
    Platform detector for Ubuntu/Linux environments.
    """

    def detect(self) -> PlatformCapabilities:
        os_version = self._get_os_version()
        privilege_level = self._get_privilege_level()

        capabilities = {
            "linux.systemd": self._has_executable("systemctl"),
            "linux.ip": self._has_executable("ip"),
            "linux.firewall.ufw": self._has_executable("ufw"),
            "linux.firewall.nftables": self._has_executable("nft"),
            "linux.firewall.iptables": self._has_executable("iptables"),
            "linux.apt": self._has_executable("apt"),
            "linux.dpkg": self._has_executable("dpkg"),
            "cross.psutil": True,
        }

        return PlatformCapabilities(
            platform=os_version,
            privilege_level=privilege_level,
            capabilities=capabilities,
        )

    def get_service_provider(self):
        from .providers import LinuxServiceProvider

        return LinuxServiceProvider()

    def get_route_provider(self):
        from .providers import LinuxRouteProvider

        return LinuxRouteProvider()

    def get_firewall_provider(self):
        from .providers import LinuxFirewallProvider

        return LinuxFirewallProvider()

    def _get_os_version(self) -> str:
        # Fallback to standard platform release
        os_version = f"Linux {platform.release()}"

        os_release_path = Path("/etc/os-release")
        if os_release_path.exists():
            try:
                with open(os_release_path, encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            # Extract value inside quotes if present
                            val = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if val:
                                os_version = val
                                break
            except Exception:
                pass

        return os_version

    def _get_privilege_level(self) -> PrivilegeLevel:
        try:
            if hasattr(os, "geteuid"):
                if os.geteuid() == 0:
                    return PrivilegeLevel.ROOT
                return PrivilegeLevel.NON_ROOT
            return PrivilegeLevel.UNKNOWN
        except Exception:
            return PrivilegeLevel.UNKNOWN

    def _has_executable(self, name: str) -> bool:
        return shutil.which(name) is not None
