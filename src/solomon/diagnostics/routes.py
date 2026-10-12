from solomon.platform.base.detection import PlatformDetector

from .base import DiagnosticCollector
from .status import CollectionResult, CollectionStatus


class RoutesCollector(DiagnosticCollector):
    def __init__(self, platform: str, detector: PlatformDetector):
        super().__init__(platform)
        self.provider = detector.get_route_provider()

    def collect(self) -> CollectionResult:
        evidence = []
        status, routes, method = self.provider.get_routes()

        if status != CollectionStatus.SUCCESS and status != CollectionStatus.PARTIAL:
            return CollectionResult(module_name=self.module_name, status=status, evidence=[])

        for route in routes:
            dest = route.get("DestinationPrefix") or route.get("dst") or "unknown"
            gw = route.get("NextHop") or route.get("gateway") or "link"
            iface = route.get("InterfaceAlias") or route.get("dev") or "unknown"

            ev = self._create_evidence(
                category="network.route",
                component=dest,
                observation=f"Route to {dest} via {gw} (dev: {iface})",
                raw_data=route,
                collection_method=method,
            )
            evidence.append(ev)

        return CollectionResult(module_name=self.module_name, status=status, evidence=evidence)
