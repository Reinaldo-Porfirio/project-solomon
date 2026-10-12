from abc import ABC, abstractmethod

from .capabilities import PlatformCapabilities


class PlatformDetector(ABC):
    """
    Abstract base class for platform and capability detection.
    """

    @abstractmethod
    def detect(self) -> PlatformCapabilities:
        """
        Detect the underlying platform, OS version, privilege level,
        and available capabilities.

        Returns:
            PlatformCapabilities object containing normalized platform data.
        """
        pass

    @abstractmethod
    def get_service_provider(self):
        pass

    @abstractmethod
    def get_route_provider(self):
        pass

    @abstractmethod
    def get_firewall_provider(self):
        pass
