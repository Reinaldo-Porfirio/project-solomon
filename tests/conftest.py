import pytest


@pytest.fixture
def fake_config_dir(tmp_path):
    return tmp_path / "solomon_config"


@pytest.fixture
def fake_evidence_data():
    return {
        "evidence_id": "EV-001",
        "source": "fake_scanner",
        "category": "network",
        "asset": "127.0.0.1",
        "component": "tcp_port",
        "observation": "port is open",
        "raw_data": {"port": 80},
        "confidence": 1.0,
        "platform": "fakeOS",
        "collection_method": "mock",
    }
