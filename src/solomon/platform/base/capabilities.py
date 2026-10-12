from dataclasses import dataclass, field
from enum import Enum


class PrivilegeLevel(Enum):
    ADMINISTRATOR = "Administrator"
    STANDARD_USER = "Standard User"
    ROOT = "Root"
    NON_ROOT = "Non-root"
    UNKNOWN = "Unknown"


@dataclass
class PlatformCapabilities:
    """
    Generic abstraction for platform capabilities.
    """

    platform: str
    privilege_level: PrivilegeLevel = PrivilegeLevel.UNKNOWN
    capabilities: dict[str, bool] = field(default_factory=dict)

    def has_capability(self, capability: str) -> bool:
        return self.capabilities.get(capability, False)
