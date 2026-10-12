import ctypes
import platform
import shutil

from solomon.platform.base.capabilities import PlatformCapabilities, PrivilegeLevel
from solomon.platform.base.detection import PlatformDetector


class WindowsDetector(PlatformDetector):
    """
    Platform detector for Windows environments.
    """

    def detect(self) -> PlatformCapabilities:
        os_version = f"Windows {platform.release()} (Build {platform.version()})"
        privilege_level = self._get_privilege_level()
        powershell_available = self._has_executable("powershell") or self._has_executable("pwsh")

        capabilities = {
            "windows.powershell": powershell_available,
            "windows.cmd": self._has_executable("cmd"),
            "windows.wmic": self._has_executable("wmic"),
            "windows.cim": powershell_available,
            "windows.services": powershell_available,
            "windows.firewall": powershell_available,
            "windows.network": powershell_available,
            "cross.psutil": True,  # Standardize that psutil is our primary means
        }

        return PlatformCapabilities(
            platform=os_version,
            privilege_level=privilege_level,
            capabilities=capabilities,
        )

    def get_service_provider(self):
        from .providers import WindowsServiceProvider

        return WindowsServiceProvider()

    def get_route_provider(self):
        from .providers import WindowsRouteProvider

        return WindowsRouteProvider()

    def get_firewall_provider(self):
        from .providers import WindowsFirewallProvider

        return WindowsFirewallProvider()

    def _get_privilege_level(self) -> PrivilegeLevel:
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                return PrivilegeLevel.ADMINISTRATOR
            return PrivilegeLevel.STANDARD_USER
        except Exception:
            return PrivilegeLevel.UNKNOWN

    def _has_executable(self, name: str) -> bool:
        return shutil.which(name) is not None
