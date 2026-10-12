from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AssetType(Enum):
    DOMAIN = "domain"
    WILDCARD_DOMAIN = "wildcard_domain"
    HOSTNAME = "hostname"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"


@dataclass
class Asset:
    asset_type: AssetType
    value: str
    normalized_value: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Extremely basic structural normalization
        if not self.normalized_value:
            self.normalized_value = self.value.strip().lower()


@dataclass
class EngagementPolicy:
    active_testing: bool = False
    max_concurrency: int = 2
    requests_per_second: int = 1
    request_timeout: int = 5
    max_retries: int = 1
    allowed_operations: list[str] = field(default_factory=list)
    blocked_operations: list[str] = field(default_factory=list)
    max_requests: int = 100
    allowed_ports: list[int] = field(default_factory=list)


@dataclass
class Scope:
    """
    Defines the authorized scope for a security assessment.
    """

    engagement_id: str
    included: list[Asset] = field(default_factory=list)
    excluded: list[Asset] = field(default_factory=list)
    policy: EngagementPolicy = field(default_factory=EngagementPolicy)
