from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.common.schemas import SecurityEvent
from app.detection.engine import DetectionEngine
from app.detection.risk import assess_risk
from app.detection.rules import BruteForceRule


def make_event(
    *,
    seconds=0,
    event_type="login",
    outcome="failure",
    source_ip="192.0.2.10",
    resource="/login",
):
    return SecurityEvent(
        event_id=uuid4(),
        timestamp=datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)
        + timedelta(seconds=seconds),
        event_type=event_type,
        outcome=outcome,
        source_ip=source_ip,
        user_id="synthetic-user",
        resource=resource,
    )


def test_brute_force_triggers_at_threshold():
    rule = BruteForceRule(threshold=5, window_seconds=300)

    findings = []
    for second in (0, 30, 60, 90, 120):
        findings.extend(rule.evaluate(make_event(seconds=second)))

    assert len(findings) == 1
    assert findings[0].rule_id == "BRUTE_FORCE_LOGIN"
    assert findings[0].event_count == 5


def test_brute_force_state_spans_separate_batches():
    rule = BruteForceRule(threshold=5, window_seconds=300)

    # Simulate two batches processed by the same worker.
    first_batch = [make_event(seconds=s) for s in (0, 30, 60)]
    second_batch = [make_event(seconds=s) for s in (90, 120)]

    first_findings = [
        finding for event in first_batch for finding in rule.evaluate(event)
    ]
    second_findings = [
        finding for event in second_batch for finding in rule.evaluate(event)
    ]

    assert first_findings == []
    assert len(second_findings) == 1


def test_brute_force_expires_old_attempts():
    rule = BruteForceRule(threshold=5, window_seconds=300)

    for second in (0, 30, 60, 90):
        rule.evaluate(make_event(seconds=second))

    findings = rule.evaluate(make_event(seconds=301))

    # The first attempt has expired; only the latest attempt remains
    # inside the five-minute window.
    assert findings == []


def test_successful_login_does_not_trigger_brute_force():
    rule = BruteForceRule(threshold=1)

    findings = rule.evaluate(make_event(outcome="success"))

    assert findings == []


def test_unauthorized_access_is_detected():
    engine = DetectionEngine(restricted_resources={"/admin/reports"})

    findings, risk = engine.evaluate(
        make_event(
            event_type="resource_access",
            outcome="denied",
            resource="/admin/reports",
        )
    )

    assert any(finding.rule_id == "UNAUTHORIZED_ACCESS" for finding in findings)
    assert risk.score == 55


def test_denylist_matches_cidr():
    engine = DetectionEngine(denylist={"192.0.2.0/24"})

    findings, risk = engine.evaluate(make_event(outcome="success"))

    assert any(f.rule_id == "DENYLIST_IP" for f in findings)
    assert risk.score == 70


def test_multiple_rules_increase_risk():
    engine = DetectionEngine(
        restricted_resources={"/admin/reports"},
        denylist={"192.0.2.10"},
    )

    findings, risk = engine.evaluate(
        make_event(
            event_type="resource_access",
            outcome="denied",
            resource="/admin/reports",
        )
    )

    assert len(findings) == 2
    assert risk.score == 100
    assert risk.severity.value == "critical"


def test_no_findings_have_zero_risk():
    risk = assess_risk([])

    assert risk.score == 0
    assert risk.reasons == ("No detection rules matched",)
