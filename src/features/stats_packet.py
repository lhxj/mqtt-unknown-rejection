"""Packet-window statistical feature extraction for the frozen MVP."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

import pandas as pd

from src.windowing.common import entropy_from_counts, population_std_from_sums, safe_divide


PACKET_STAT_FEATURES = (
    "num_pkts_total",
    "num_bytes_total",
    "mean_pkt_len",
    "std_pkt_len",
    "min_pkt_len",
    "max_pkt_len",
    "mean_iat",
    "std_iat",
    "min_iat",
    "max_iat",
    "tcp_ack_count",
    "tcp_syn_count",
    "tcp_fin_count",
    "tcp_rst_count",
    "tcp_psh_count",
    "mqtt_pkt_count",
    "mqtt_pkt_ratio",
    "mqtt_msgtype_entropy",
    "mqtt_msglen_mean",
    "mqtt_msglen_std",
    "uplink_pkt_count",
    "downlink_pkt_count",
    "uplink_byte_count",
    "downlink_byte_count",
    "direction_pkt_ratio",
    "direction_byte_ratio",
)


@dataclass
class PacketStatsAccumulator:
    """Merge-friendly accumulator for one broker-facing packet window."""

    packet_count: int = 0
    byte_sum: float = 0.0

    pkt_len_count: int = 0
    pkt_len_sum: float = 0.0
    pkt_len_sumsq: float = 0.0
    pkt_len_min: float = float("inf")
    pkt_len_max: float = float("-inf")

    iat_count: int = 0
    iat_sum: float = 0.0
    iat_sumsq: float = 0.0
    iat_min: float = float("inf")
    iat_max: float = float("-inf")

    tcp_ack_count: int = 0
    tcp_syn_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    tcp_psh_count: int = 0

    mqtt_pkt_count: int = 0
    mqtt_msglen_count: int = 0
    mqtt_msglen_sum: float = 0.0
    mqtt_msglen_sumsq: float = 0.0

    uplink_pkt_count: int = 0
    downlink_pkt_count: int = 0
    uplink_byte_count: float = 0.0
    downlink_byte_count: float = 0.0

    mqtt_msgtype_counts: Counter[int] = field(default_factory=Counter)
    last_timestamp: pd.Timestamp | None = None
    out_of_order_boundaries: int = 0

    def merge_partial(self, partial: dict[str, float | int | pd.Timestamp | None]) -> None:
        """Merge one pre-aggregated chunk-level partial into this window."""

        self.packet_count += int(partial["packet_count"])
        self.byte_sum += float(partial["byte_sum"])

        self.pkt_len_count += int(partial["pkt_len_count"])
        self.pkt_len_sum += float(partial["pkt_len_sum"])
        self.pkt_len_sumsq += float(partial["pkt_len_sumsq"])
        self.pkt_len_min = min(self.pkt_len_min, float(partial["pkt_len_min"]))
        self.pkt_len_max = max(self.pkt_len_max, float(partial["pkt_len_max"]))

        self.iat_count += int(partial["iat_count"])
        self.iat_sum += float(partial["iat_sum"])
        self.iat_sumsq += float(partial["iat_sumsq"])
        self.iat_min = min(self.iat_min, float(partial["iat_min"]))
        self.iat_max = max(self.iat_max, float(partial["iat_max"]))

        self.tcp_ack_count += int(partial["tcp_ack_count"])
        self.tcp_syn_count += int(partial["tcp_syn_count"])
        self.tcp_fin_count += int(partial["tcp_fin_count"])
        self.tcp_rst_count += int(partial["tcp_rst_count"])
        self.tcp_psh_count += int(partial["tcp_psh_count"])

        self.mqtt_pkt_count += int(partial["mqtt_pkt_count"])
        self.mqtt_msglen_count += int(partial["mqtt_msglen_count"])
        self.mqtt_msglen_sum += float(partial["mqtt_msglen_sum"])
        self.mqtt_msglen_sumsq += float(partial["mqtt_msglen_sumsq"])

        self.uplink_pkt_count += int(partial["uplink_pkt_count"])
        self.downlink_pkt_count += int(partial["downlink_pkt_count"])
        self.uplink_byte_count += float(partial["uplink_byte_count"])
        self.downlink_byte_count += float(partial["downlink_byte_count"])

        partial_last_ts = partial.get("last_timestamp")
        if isinstance(partial_last_ts, pd.Timestamp):
            if self.last_timestamp is None or partial_last_ts > self.last_timestamp:
                self.last_timestamp = partial_last_ts

    def update_msgtype_counts(self, values: Iterable[int]) -> None:
        """Merge MQTT message-type counts for entropy computation."""

        self.mqtt_msgtype_counts.update(int(value) for value in values)

    def add_iat_boundary(self, delta_seconds: float) -> None:
        """Add a cross-chunk inter-arrival interval."""

        if pd.isna(delta_seconds) or delta_seconds < 0:
            self.out_of_order_boundaries += 1
            return

        delta_value = float(delta_seconds)
        self.iat_count += 1
        self.iat_sum += delta_value
        self.iat_sumsq += delta_value * delta_value
        self.iat_min = min(self.iat_min, delta_value)
        self.iat_max = max(self.iat_max, delta_value)

    def finalize(self) -> dict[str, float | int]:
        """Materialize the frozen packet-window feature set."""

        mean_pkt_len = safe_divide(self.pkt_len_sum, self.pkt_len_count)
        std_pkt_len = population_std_from_sums(
            self.pkt_len_count,
            self.pkt_len_sum,
            self.pkt_len_sumsq,
        )
        mean_iat = safe_divide(self.iat_sum, self.iat_count)
        std_iat = population_std_from_sums(
            self.iat_count,
            self.iat_sum,
            self.iat_sumsq,
        )
        mqtt_msglen_mean = safe_divide(self.mqtt_msglen_sum, self.mqtt_msglen_count)
        mqtt_msglen_std = population_std_from_sums(
            self.mqtt_msglen_count,
            self.mqtt_msglen_sum,
            self.mqtt_msglen_sumsq,
        )

        return {
            "num_pkts_total": int(self.packet_count),
            "num_bytes_total": float(self.byte_sum),
            "mean_pkt_len": mean_pkt_len,
            "std_pkt_len": std_pkt_len,
            "min_pkt_len": 0.0 if self.pkt_len_count == 0 else float(self.pkt_len_min),
            "max_pkt_len": 0.0 if self.pkt_len_count == 0 else float(self.pkt_len_max),
            "mean_iat": mean_iat,
            "std_iat": std_iat,
            "min_iat": 0.0 if self.iat_count == 0 else float(self.iat_min),
            "max_iat": 0.0 if self.iat_count == 0 else float(self.iat_max),
            "tcp_ack_count": int(self.tcp_ack_count),
            "tcp_syn_count": int(self.tcp_syn_count),
            "tcp_fin_count": int(self.tcp_fin_count),
            "tcp_rst_count": int(self.tcp_rst_count),
            "tcp_psh_count": int(self.tcp_psh_count),
            "mqtt_pkt_count": int(self.mqtt_pkt_count),
            "mqtt_pkt_ratio": safe_divide(self.mqtt_pkt_count, self.packet_count),
            "mqtt_msgtype_entropy": entropy_from_counts(self.mqtt_msgtype_counts.values()),
            "mqtt_msglen_mean": mqtt_msglen_mean,
            "mqtt_msglen_std": mqtt_msglen_std,
            "uplink_pkt_count": int(self.uplink_pkt_count),
            "downlink_pkt_count": int(self.downlink_pkt_count),
            "uplink_byte_count": float(self.uplink_byte_count),
            "downlink_byte_count": float(self.downlink_byte_count),
            "direction_pkt_ratio": safe_divide(
                self.uplink_pkt_count,
                max(self.downlink_pkt_count, 1),
            ),
            "direction_byte_ratio": safe_divide(
                self.uplink_byte_count,
                max(self.downlink_byte_count, 1.0),
            ),
        }
