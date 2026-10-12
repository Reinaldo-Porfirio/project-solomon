from solomon.core.scope import Asset, AssetType, EngagementPolicy, Scope
from solomon.pentest.guard import TargetGuard
from solomon.pentest.models import AuthorizationStatus, Engagement, OperationType, TargetDecision


def build_engagement(status=AuthorizationStatus.ACTIVE, active_testing=False):
    return Engagement(
        engagement_id="ENG-TEST",
        name="Test",
        authorization_status=status,
        scope=Scope(
            engagement_id="ENG-TEST",
            included=[
                Asset(AssetType.WILDCARD_DOMAIN, "*.example.com"),
                Asset(AssetType.DOMAIN, "example.com"),
            ],
            excluded=[
                Asset(AssetType.HOSTNAME, "admin.example.com"),
                Asset(AssetType.CIDR, "192.168.1.0/24"),
            ],
            policy=EngagementPolicy(
                active_testing=active_testing, blocked_operations=[OperationType.WEB_SCAN.name]
            ),
        ),
    )


def test_guard_authorization_status():
    eng = build_engagement(status=AuthorizationStatus.UNDECLARED)
    res = TargetGuard.check(eng, "example.com", OperationType.DNS_LOOKUP)
    assert res.decision == TargetDecision.BLOCKED_NOT_AUTHORIZED


def test_guard_policy_blocks():
    eng = build_engagement(active_testing=False)
    # Active validation blocked by active_testing=False
    res = TargetGuard.check(eng, "example.com", OperationType.ACTIVE_VALIDATION)
    assert res.decision == TargetDecision.BLOCKED_POLICY

    # Web Scan explicitly blocked
    eng.scope.policy.active_testing = True
    res = TargetGuard.check(eng, "example.com", OperationType.WEB_SCAN)
    assert res.decision == TargetDecision.BLOCKED_POLICY


def test_guard_exclusions():
    eng = build_engagement()
    # Included wildcard, but excluded explicitly
    res = TargetGuard.check(eng, "admin.example.com", OperationType.DNS_LOOKUP)
    assert res.decision == TargetDecision.BLOCKED_EXCLUDED

    # Excluded CIDR
    res = TargetGuard.check(eng, "192.168.1.10", OperationType.DNS_LOOKUP)
    assert res.decision == TargetDecision.BLOCKED_EXCLUDED


def test_guard_inclusions():
    eng = build_engagement()
    res = TargetGuard.check(eng, "api.example.com", OperationType.DNS_LOOKUP)
    assert res.decision == TargetDecision.ALLOWED

    res = TargetGuard.check(eng, "example.com", OperationType.DNS_LOOKUP)
    assert res.decision == TargetDecision.ALLOWED


def test_guard_out_of_scope():
    eng = build_engagement()
    res = TargetGuard.check(eng, "notexample.com", OperationType.DNS_LOOKUP)
    assert res.decision == TargetDecision.BLOCKED_OUT_OF_SCOPE
