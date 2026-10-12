from abc import ABC, abstractmethod
from typing import Any

from solomon.diagnostics.status import CollectionStatus


class ServiceProvider(ABC):
    @abstractmethod
    def get_services(self) -> tuple[CollectionStatus, list[dict[str, Any]], str]:
        """Returns (status, services_list, collection_method)."""
        pass


class RouteProvider(ABC):
    @abstractmethod
    def get_routes(self) -> tuple[CollectionStatus, list[dict[str, Any]], str]:
        pass


class FirewallProvider(ABC):
    @abstractmethod
    def get_firewall_state(self) -> tuple[CollectionStatus, dict[str, Any], str]:
        pass
