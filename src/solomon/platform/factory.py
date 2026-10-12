import platform

from .base.detection import PlatformDetector


def get_platform_detector() -> PlatformDetector:
    """
    Factory function to return the correct platform detector for the current host OS.
    """
    os_name = platform.system().lower()

    if os_name == "windows":
        from .windows.detection import WindowsDetector

        return WindowsDetector()

    # Default to Ubuntu/Linux detector for all non-Windows systems in this milestone
    from .linux.ubuntu.detection import UbuntuDetector

    return UbuntuDetector()
