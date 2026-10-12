from solomon.platform.base.detection import PlatformDetector

from .base import DiagnosticCollector
from .status import CollectionResult, CollectionStatus


class FirewallCollector(DiagnosticCollector):
    def __init__(self, platform: str, detector: PlatformDetector):
        super().__init__(platform)
        self.provider = detector.get_firewall_provider()

    def collect(self) -> CollectionResult:
        evidence = []
        status, state, method = self.provider.get_firewall_state()

        if status != CollectionStatus.SUCCESS and status != CollectionStatus.PARTIAL:
            return CollectionResult(module_name=self.module_name, status=status, evidence=[])

        ev = self._create_evidence(
            category="network.firewall",
            component=state.get("backend", "firewall"),
            observation=f"Firewall state collected using {method}",
            raw_data=state,
            collection_method=method,
        )
        evidence.append(ev)

        return CollectionResult(module_name=self.module_name, status=status, evidence=evidence)
