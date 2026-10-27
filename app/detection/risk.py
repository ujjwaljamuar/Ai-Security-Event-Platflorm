from dataclasses import dataclass

from app.common.schemas import AlertSeverity
from app.detection.rules import DetectionFinding


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: AlertSeverity
    reasons: tuple[str, ...]


RULE_BASE_SCORES = {
    "BRUTE_FORCE_LOGIN": 70,
    "UNAUTHORIZED_ACCESS": 55,
    "DENYLIST_IP": 70,
}


def assess_risk(
    findings: list[DetectionFinding],
) -> RiskAssessment:
    """Combine findings into a deterministic, explainable risk score."""
    if not findings:
        return RiskAssessment(
            score=0,
            severity=AlertSeverity.LOW,
            reasons=("No detection rules matched",),
        )

    # Add rule scores, but cap the overall score at 100.
    raw_score = sum(RULE_BASE_SCORES.get(finding.rule_id, 20) for finding in findings)

    score = min(raw_score, 100)

    if score >= 90:
        severity = AlertSeverity.CRITICAL
    elif score >= 70:
        severity = AlertSeverity.HIGH
    elif score >= 40:
        severity = AlertSeverity.MEDIUM
    else:
        severity = AlertSeverity.LOW

    reasons = tuple(f"{finding.rule_id}: {finding.description}" for finding in findings)

    return RiskAssessment(
        score=score,
        severity=severity,
        reasons=reasons,
    )
