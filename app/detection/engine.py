from app.common.schemas import SecurityEvent
from app.detection.risk import RiskAssessment, assess_risk
from app.detection.rules import (
    BruteForceRule,
    DenylistRule,
    DetectionFinding,
    UnauthorizedAccessRule,
)


class DetectionEngine:
    """Run configured rules and assess the resulting risk."""

    def __init__(
        self,
        brute_force_threshold: int = 5,
        brute_force_window_seconds: int = 300,
        restricted_resources: set[str] | None = None,
        denylist: set[str] | None = None,
    ):
        self.rules = [
            BruteForceRule(
                threshold=brute_force_threshold,
                window_seconds=brute_force_window_seconds,
            ),
            UnauthorizedAccessRule(
                restricted_resources=restricted_resources or {"/admin/reports"}
            ),
            DenylistRule(entries=denylist or set()),
        ]

    def evaluate(
        self,
        event: SecurityEvent,
    ) -> tuple[list[DetectionFinding], RiskAssessment]:
        findings = []

        for rule in self.rules:
            findings.extend(rule.evaluate(event))

        return findings, assess_risk(findings)

    def evaluate_with_history(
        self,
        event: SecurityEvent,
        failed_login_timestamps: list,
    ):
        """Evaluate an event using externally managed brute-force history."""
        brute_force_rule = self.rules[0]
        findings, updated_history = brute_force_rule.evaluate_with_history(
            event,
            failed_login_timestamps,
        )

        for rule in self.rules[1:]:
            findings.extend(rule.evaluate(event))

        return findings, assess_risk(findings), updated_history
