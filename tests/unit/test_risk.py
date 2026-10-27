from datetime import datetime, timezone

import pytest

from app.common.schemas import AlertSeverity
from app.detection.risk import assess_risk
from app.detection.rules import DetectionFinding


def make_finding(rule_id: str) -> DetectionFinding:
    timestamp = datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)

    return DetectionFinding(
        rule_id=rule_id,
        source_ip="192.0.2.10",
        event_count=5,
        first_seen=timestamp,
        last_seen=timestamp,
        description="Synthetic test finding",
        evidence={},
    )


@pytest.mark.parametrize(
    ("rule_id", "expected_score", "expected_severity"),
    [
        ("BRUTE_FORCE_LOGIN", 70, AlertSeverity.HIGH),
        ("UNAUTHORIZED_ACCESS", 55, AlertSeverity.MEDIUM),
        ("DENYLIST_IP", 70, AlertSeverity.HIGH),
    ],
)
def test_single_rule_risk_assessment(
    rule_id,
    expected_score,
    expected_severity,
):
    result = assess_risk([make_finding(rule_id)])

    assert result.score == expected_score
    assert result.severity == expected_severity


def test_combined_findings_cap_score_at_100():
    result = assess_risk(
        [
            make_finding("BRUTE_FORCE_LOGIN"),
            make_finding("DENYLIST_IP"),
        ]
    )

    assert result.score == 100
    assert result.severity == AlertSeverity.CRITICAL


def test_no_findings_have_zero_risk():
    result = assess_risk([])

    assert result.score == 0
    assert result.severity == AlertSeverity.LOW
