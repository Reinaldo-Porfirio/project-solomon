import logging

from solomon.platform.base.detection import PlatformDetector

from .cpu import CPUCollector
from .firewall import FirewallCollector
from .memory import MemoryCollector
from .network import NetworkCollector
from .processes import ProcessesCollector
from .routes import RoutesCollector
from .services import ServicesCollector
from .sockets import SocketsCollector
from .status import CollectionResult, CollectionStatus
from .storage import StorageCollector


class DiagnosticsEngine:
    """
    Orchestrates the diagnostic collectors.
    """

    def __init__(self, detector: PlatformDetector):
        self.detector = detector
        capabilities = detector.detect()

        self.collectors = [
            CPUCollector(platform=capabilities.platform),
            MemoryCollector(platform=capabilities.platform),
            StorageCollector(platform=capabilities.platform),
            ProcessesCollector(platform=capabilities.platform),
            NetworkCollector(platform=capabilities.platform),
            SocketsCollector(platform=capabilities.platform),
            ServicesCollector(platform=capabilities.platform, detector=detector),
            RoutesCollector(platform=capabilities.platform, detector=detector),
            FirewallCollector(platform=capabilities.platform, detector=detector),
        ]

    def run(self) -> dict[str, CollectionResult]:
        results = {}
        for collector in self.collectors:
            try:
                res = collector.collect()
                results[res.module_name] = res
            except Exception as e:
                logging.getLogger("solomon").error(
                    f"Collector {collector.__class__.__name__} failed catastrophically: {e}"
                )
                results[collector.module_name] = CollectionResult(
                    module_name=collector.module_name,
                    status=CollectionStatus.FAILED,
                    evidence=[],
                    message=str(e),
                )

        return results
