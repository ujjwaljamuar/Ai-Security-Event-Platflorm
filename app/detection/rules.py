from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network

from app.common.schemas import SecurityEvent


@dataclass(frozen=True)
class DetectionFinding:
    rule_id: str
    source_ip: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    evidence: dict


class BruteForceRule:
    """Detect repeated failed logins within a rolling time window."""

    rule_id = "BRUTE_FORCE_LOGIN"

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 300,
    ):
        if threshold < 1:
            raise ValueError("threshold must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._failed_logins: dict[str, list[datetime]] = {}

    def evaluate(self, event: SecurityEvent) -> list[DetectionFinding]:
        if event.event_type != "login" or event.outcome != "failure":
            return []

        timestamps = self._failed_logins.setdefault(event.source_ip, [])
        timestamps.append(event.timestamp)

        cutoff = event.timestamp - self.window

        # Keep timestamps that are exactly on the window boundary.
        timestamps[:] = [ts for ts in timestamps if cutoff <= ts <= event.timestamp]

        if len(timestamps) < self.threshold:
            return []

        return [
            DetectionFinding(
                rule_id=self.rule_id,
                source_ip=event.source_ip,
                event_count=len(timestamps),
                first_seen=timestamps[0],
                last_seen=event.timestamp,
                description=(
                    f"{len(timestamps)} failed login attempts from "
                    f"{event.source_ip} within {self.window.total_seconds():.0f}s"
                ),
                evidence={
                    "threshold": self.threshold,
                    "window_seconds": int(self.window.total_seconds()),
                },
            )
        ]

    def evaluate_with_history(
        self,
        event: SecurityEvent,
        history: list[datetime],
    ) -> tuple[list[DetectionFinding], list[datetime]]:
        """Evaluate using caller-managed history without mutating rule state."""
        cutoff = event.timestamp - self.window

        timestamps = [ts for ts in history if ts > cutoff]

        if event.event_type == "login" and event.outcome == "failure":
            timestamps.append(event.timestamp)

        timestamps.sort()

        active_timestamps = [ts for ts in timestamps if cutoff <= ts <= event.timestamp]

        if len(active_timestamps) < self.threshold:
            return [], timestamps

        finding = DetectionFinding(
            rule_id=self.rule_id,
            source_ip=event.source_ip,
            event_count=len(active_timestamps),
            first_seen=active_timestamps[0],
            last_seen=event.timestamp,
            description=(
                f"{len(active_timestamps)} failed login attempts from "
                f"{event.source_ip} within "
                f"{self.window.total_seconds():.0f}s"
            ),
            evidence={
                "threshold": self.threshold,
                "window_seconds": int(self.window.total_seconds()),
            },
        )

        return [finding], timestamps


class UnauthorizedAccessRule:
    """Detect denied attempts to access restricted resources."""

    rule_id = "UNAUTHORIZED_ACCESS"

    def __init__(self, restricted_resources: set[str]):
        self.restricted_resources = set(restricted_resources)

    def evaluate(self, event: SecurityEvent) -> list[DetectionFinding]:
        if event.outcome != "denied" or event.resource not in self.restricted_resources:
            return []

        return [
            DetectionFinding(
                rule_id=self.rule_id,
                source_ip=event.source_ip,
                event_count=1,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                description=(f"Access denied to restricted resource {event.resource}"),
                evidence={
                    "resource": event.resource,
                    "event_id": str(event.event_id),
                },
            )
        ]


class DenylistRule:
    """Match event source IPs against configured IPs or CIDR networks."""

    rule_id = "DENYLIST_IP"

    def __init__(self, entries: set[str]):
        self.networks = tuple(ip_network(entry, strict=False) for entry in entries)

    def evaluate(self, event: SecurityEvent) -> list[DetectionFinding]:
        address = ip_address(event.source_ip)

        matching_networks = [
            str(network)
            for network in self.networks
            if address.version == network.version and address in network
        ]

        if not matching_networks:
            return []

        return [
            DetectionFinding(
                rule_id=self.rule_id,
                source_ip=event.source_ip,
                event_count=1,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                description=f"Event originated from denylisted IP {event.source_ip}",
                evidence={"matching_networks": matching_networks},
            )
        ]
