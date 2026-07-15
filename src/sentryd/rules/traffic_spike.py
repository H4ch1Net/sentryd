"""Traffic volume spike detection per source host.

Traffic is bucketed into fixed intervals per source IP; an exponentially
weighted moving average (EWMA) of completed buckets forms the host's
baseline. A bucket alerts when it exceeds ``spike_ratio`` x baseline AND an
absolute byte floor (so a quiet host going from 2 to 11 packets never pages
anyone).

Buckets are evaluated when they complete — i.e. when a later event from the
same host arrives — so the trailing partial bucket of a capture is never
judged. All timing uses event timestamps: replaying a pcap gives the same
answers as watching the wire.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentryd.core.alerts import Alert, Severity
from sentryd.core.events import Event
from sentryd.rules.base import Rule, register


@dataclass
class _HostWindow:
    bucket_idx: int
    bytes: int = 0
    packets: int = 0
    ewma: float | None = None  # baseline bytes per bucket
    buckets_seen: int = 0  # completed buckets folded into the baseline


@register
class TrafficSpikeRule(Rule):
    rule_id = "traffic_spike"

    def __init__(
        self,
        bucket_seconds: float = 5.0,
        spike_ratio: float = 5.0,
        min_bucket_bytes: int = 50_000,
        ewma_alpha: float = 0.3,
        warmup_buckets: int = 3,
    ) -> None:
        self.bucket_seconds = float(bucket_seconds)
        self.spike_ratio = float(spike_ratio)
        self.min_bucket_bytes = int(min_bucket_bytes)
        self.ewma_alpha = float(ewma_alpha)
        self.warmup_buckets = int(warmup_buckets)
        self._hosts: dict[str, _HostWindow] = {}
        self._last_sweep_idx: int | None = None

    # Hosts idle this many buckets are forgotten (their baseline has decayed
    # to noise anyway); bounds per-host state on long live captures where
    # spoofed sources would otherwise accumulate forever.
    IDLE_EXPIRY_BUCKETS = 120

    def process(self, event: Event) -> list[Alert]:
        if event.src_ip is None or event.length <= 0:
            return []

        idx = int(event.ts // self.bucket_seconds)
        self._maybe_sweep(idx)
        window = self._hosts.get(event.src_ip)
        if window is None:
            self._hosts[event.src_ip] = _HostWindow(bucket_idx=idx)
            window = self._hosts[event.src_ip]

        alerts: list[Alert] = []
        if idx > window.bucket_idx:
            alerts = self._finalize_bucket(event.src_ip, window)
            # Idle buckets between the completed one and now decay the
            # baseline toward zero, exactly as if empty buckets streamed by.
            gap = min(idx - window.bucket_idx - 1, 100)
            if gap and window.ewma is not None:
                window.ewma *= (1.0 - self.ewma_alpha) ** gap
                window.buckets_seen += gap
            window.bucket_idx = idx
            window.bytes = 0
            window.packets = 0

        window.bytes += event.length
        window.packets += 1
        return alerts

    def _maybe_sweep(self, idx: int) -> None:
        if self._last_sweep_idx is None:
            self._last_sweep_idx = idx
            return
        if idx - self._last_sweep_idx < self.IDLE_EXPIRY_BUCKETS:
            return
        self._last_sweep_idx = idx
        for host in [
            host
            for host, window in self._hosts.items()
            if idx - window.bucket_idx > self.IDLE_EXPIRY_BUCKETS
        ]:
            del self._hosts[host]

    def _finalize_bucket(self, host: str, window: _HostWindow) -> list[Alert]:
        completed_bytes = window.bytes
        completed_packets = window.packets
        baseline = window.ewma

        alerts: list[Alert] = []
        if (
            baseline is not None
            and window.buckets_seen >= self.warmup_buckets
            and baseline > 0
            and completed_bytes >= self.min_bucket_bytes
            and completed_bytes > self.spike_ratio * baseline
        ):
            observed_ratio = completed_bytes / baseline
            severity = (
                Severity.HIGH
                if observed_ratio >= 2 * self.spike_ratio
                else Severity.MEDIUM
            )
            confidence = round(
                min(0.90, 0.50 + 0.10 * (observed_ratio / self.spike_ratio)), 2
            )
            bucket_end = (window.bucket_idx + 1) * self.bucket_seconds
            alerts.append(
                Alert(
                    rule_id=self.rule_id,
                    severity=severity,
                    confidence=confidence,
                    title=(
                        f"Traffic spike from {host}: {completed_bytes:,} bytes in "
                        f"{self.bucket_seconds:g}s ({observed_ratio:.1f}x baseline)"
                    ),
                    ts=bucket_end,
                    src=host,
                    dst=None,
                    evidence={
                        "bucket_bytes": completed_bytes,
                        "bucket_packets": completed_packets,
                        "bucket_seconds": self.bucket_seconds,
                        "baseline_bytes": round(baseline, 1),
                        "observed_ratio": round(observed_ratio, 2),
                        "spike_ratio_threshold": self.spike_ratio,
                        "min_bucket_bytes": self.min_bucket_bytes,
                    },
                )
            )

        # Fold the completed bucket into the baseline (spikes included — the
        # baseline adapts, and the engine's cooldown merges an ongoing flood).
        if window.ewma is None:
            window.ewma = float(completed_bytes)
        else:
            window.ewma = (
                self.ewma_alpha * completed_bytes
                + (1.0 - self.ewma_alpha) * window.ewma
            )
        window.buckets_seen += 1
        return alerts
