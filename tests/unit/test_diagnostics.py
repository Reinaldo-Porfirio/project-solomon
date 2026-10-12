from collections import namedtuple
from unittest import mock

import psutil

from solomon.diagnostics.cpu import CPUCollector
from solomon.diagnostics.memory import MemoryCollector
from solomon.diagnostics.status import CollectionStatus
from solomon.diagnostics.storage import StorageCollector


@mock.patch("psutil.cpu_count", side_effect=[8, 4])
@mock.patch("psutil.cpu_percent", return_value=[10.5, 20.0, 5.0, 15.0, 0.0, 0.0, 0.0, 0.0])
def test_cpu_collector(mock_cpu_percent, mock_cpu_count):
    collector = CPUCollector(platform="MockOS")
    evidence_list = collector.collect().evidence

    assert len(evidence_list) == 1
    ev = evidence_list[0]

    assert ev.category == "hardware.cpu"
    assert ev.component == "cpu_load"
    assert ev.raw_data["logical_cores"] == 8
    assert ev.raw_data["physical_cores"] == 4
    assert ev.confidence == 1.0


@mock.patch("psutil.virtual_memory")
@mock.patch("psutil.swap_memory")
def test_memory_collector(mock_swap, mock_vmem):
    vmem_mock = mock.Mock()
    vmem_mock.total = 16 * 1024**3
    vmem_mock.available = 8 * 1024**3
    vmem_mock.percent = 50.0
    mock_vmem.return_value = vmem_mock

    swap_mock = mock.Mock()
    swap_mock.total = 4 * 1024**3
    swap_mock.used = 1 * 1024**3
    swap_mock.percent = 25.0
    mock_swap.return_value = swap_mock

    collector = MemoryCollector(platform="MockOS")
    evidence_list = collector.collect().evidence

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.category == "hardware.memory"
    assert ev.raw_data["total_bytes"] == 16 * 1024**3


@mock.patch("psutil.disk_partitions")
@mock.patch("psutil.disk_usage")
def test_storage_collector(mock_disk_usage, mock_disk_partitions):
    Part = namedtuple("Part", ["device", "mountpoint", "fstype", "opts"])
    Usage = namedtuple("Usage", ["total", "used", "free", "percent"])

    mock_disk_partitions.return_value = [
        Part(device="/dev/sda1", mountpoint="/", fstype="ext4", opts="rw"),
    ]
    mock_disk_usage.return_value = Usage(total=1000, used=500, free=500, percent=50.0)

    collector = StorageCollector(platform="MockOS")
    evidence_list = collector.collect().evidence

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.category == "hardware.storage"
    assert ev.component == "/"
    assert ev.raw_data["fstype"] == "ext4"


@mock.patch("psutil.disk_partitions", return_value=[mock.Mock(mountpoint="/locked")])
@mock.patch("psutil.disk_usage", side_effect=PermissionError("Access Denied"))
def test_storage_collector_permission_error(mock_disk_usage, mock_disk_partitions):
    # PermissionErrors during storage parsing should be ignored rather than breaking collection
    collector = StorageCollector(platform="MockOS")
    evidence_list = collector.collect().evidence

    assert len(evidence_list) == 0


@mock.patch("psutil.process_iter")
def test_processes_collector(mock_process_iter):
    # Mock a single process
    mock_proc = mock.Mock()
    mock_proc.info = {"pid": 1, "name": "systemd", "username": "root"}
    mock_proc.cpu_percent.return_value = 0.5
    mock_proc.memory_percent.return_value = 0.1
    mock_proc.cmdline.side_effect = psutil.AccessDenied()

    mock_process_iter.return_value = [mock_proc]

    from solomon.diagnostics.processes import ProcessesCollector

    collector = ProcessesCollector(platform="MockOS")
    res = collector.collect()

    assert res.status == "SUCCESS"
    assert len(res.evidence) == 1
    ev = res.evidence[0]
    assert ev.raw_data["pid"] == 1
    assert ev.raw_data["cmdline"] == []


@mock.patch("psutil.net_if_addrs")
@mock.patch("psutil.net_if_stats")
def test_network_collector(mock_stats, mock_addrs):
    mock_addrs.return_value = {}
    mock_stats.return_value = {}

    from solomon.diagnostics.network import NetworkCollector

    collector = NetworkCollector(platform="MockOS")
    res = collector.collect()

    assert res.status == "SUCCESS"
    assert len(res.evidence) == 0


@mock.patch("psutil.cpu_count", side_effect=Exception("Critical Failure"))
def test_collector_failure_handling(mock_cpu_count):
    collector = CPUCollector(platform="MockOS")
    res = collector.collect()
    assert res.status == CollectionStatus.FAILED
    assert "Critical Failure" in res.message
