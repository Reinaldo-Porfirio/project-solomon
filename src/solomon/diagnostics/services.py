from solomon.platform.base.detection import PlatformDetector

from .base import DiagnosticCollector
from .status import CollectionResult, CollectionStatus


class ServicesCollector(DiagnosticCollector):
    def __init__(self, platform: str, detector: PlatformDetector):
        super().__init__(platform)
        self.provider = detector.get_service_provider()

    def collect(self) -> CollectionResult:
        evidence = []
        status, services, method = self.provider.get_services()

        if status != CollectionStatus.SUCCESS and status != CollectionStatus.PARTIAL:
            return CollectionResult(module_name=self.module_name, status=status, evidence=[])

        for svc in services:
            ev = self._create_evidence(
                category="os.service",
                component=svc.get("Name") or svc.get("unit") or "unknown",
                observation=(
                    f"Service {svc.get('DisplayName') or svc.get('unit')} "
                    f"is {svc.get('State') or svc.get('sub')}"
                ),
                raw_data=svc,
                collection_method=method,
            )
            evidence.append(ev)

        return CollectionResult(module_name=self.module_name, status=status, evidence=evidence)
