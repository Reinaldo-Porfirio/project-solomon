from dataclasses import FrozenInstanceError

import pytest

from solomon.core.evidence import Evidence


def test_evidence_immutability(fake_evidence_data):
    """Ensure that Evidence is immutable after creation."""
    evidence = Evidence(**fake_evidence_data)

    assert evidence.evidence_id == "EV-001"

    with pytest.raises(FrozenInstanceError):
        evidence.confidence = 0.5


def test_evidence_timestamp(fake_evidence_data):
    evidence = Evidence(**fake_evidence_data)
    assert evidence.timestamp is not None
    assert isinstance(evidence.timestamp, str)
