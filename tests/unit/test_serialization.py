import dataclasses
import json

from solomon.core.scope import Asset, AssetType, EngagementPolicy, Scope
from solomon.pentest.models import AuthorizationStatus, Engagement


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, (AssetType, AuthorizationStatus)):
            return o.value
        return super().default(o)


def test_engagement_serialization():
    scope = Scope(
        engagement_id="ENG-1",
        included=[Asset(AssetType.DOMAIN, "example.com", "example.com")],
        excluded=[],
        policy=EngagementPolicy(active_testing=True),
    )
    eng = Engagement(
        engagement_id="ENG-1",
        name="Test",
        authorization_status=AuthorizationStatus.ACTIVE,
        scope=scope,
        created_at="2026-01-01T00:00:00Z",
    )

    # Serialize
    json_data = json.dumps(eng, cls=EnhancedJSONEncoder)

    # Deserialize conceptually
    data = json.loads(json_data)
    assert data["engagement_id"] == "ENG-1"
    assert data["authorization_status"] == "ACTIVE"
    assert data["scope"]["policy"]["active_testing"] is True
    assert data["scope"]["included"][0]["value"] == "example.com"
