"""Conservative semantic-lite feature extraction for frozen-scope MQTT windows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pandas as pd

from src.windowing.common import safe_divide


SEMANTIC_LITE_FEATURES = (
    "reconnect_frequency",
    "order_anomaly_ratio_lite",
    "missing_handshake_ratio_lite",
)

CONNECT = 1
CONNACK = 2
DISCONNECT = 14
ACTIVITY_TYPES = {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}


@dataclass(frozen=True)
class SemanticLiteResult:
    """Feature values plus audit metadata for one window."""

    reconnect_frequency: float
    order_anomaly_ratio_lite: float
    missing_handshake_ratio_lite: float
    mqtt_event_count: int
    connect_count: int
    eligible_connect_count: int
    sparse_semantic_inputs: bool
    orphan_connack_count: int
    activity_before_connect_count: int
    repeated_connect_jump_count: int

    def as_feature_dict(self) -> dict[str, float]:
        """Return only the model-facing semantic-lite feature columns."""

        return {
            "reconnect_frequency": self.reconnect_frequency,
            "order_anomaly_ratio_lite": self.order_anomaly_ratio_lite,
            "missing_handshake_ratio_lite": self.missing_handshake_ratio_lite,
        }

    def as_metadata_dict(self) -> dict[str, int | bool]:
        """Return semantic audit metadata that stays outside model inputs."""

        return {
            "semantic_mqtt_event_count": self.mqtt_event_count,
            "semantic_connect_count": self.connect_count,
            "semantic_eligible_connect_count": self.eligible_connect_count,
            "semantic_sparse_inputs": self.sparse_semantic_inputs,
            "semantic_orphan_connack_count": self.orphan_connack_count,
            "semantic_activity_before_connect_count": self.activity_before_connect_count,
            "semantic_repeated_connect_jump_count": self.repeated_connect_jump_count,
        }


def _normalize_events(
    events: Iterable[tuple[pd.Timestamp, int, str]],
) -> list[tuple[pd.Timestamp, int, str]]:
    """Sort MQTT events within a window by time and preserve coarse direction."""

    normalized = [
        (timestamp, int(message_type), str(direction))
        for timestamp, message_type, direction in events
        if pd.notna(message_type)
    ]
    normalized.sort(key=lambda item: (item[0], item[1], item[2]))
    return normalized


def compute_semantic_lite_features(
    events: Iterable[tuple[pd.Timestamp, int, str]],
    *,
    window_duration_seconds: float = 5.0,
    handshake_timeout_seconds: float = 1.0,
) -> SemanticLiteResult:
    """Compute the frozen semantic-lite feature set for one endpoint window.

    Conservative rules:
    - `reconnect_frequency` counts only repeated CONNECT events beyond the first
      and normalizes them by the fixed 5-second window duration.
    - `order_anomaly_ratio_lite` counts three local anomalies:
      1. MQTT activity before the first CONNECT, but only when a CONNECT is also
         present later in the same window.
      2. CONNACK before the first CONNECT, again only when a later CONNECT exists.
      3. CONNECT events after the first CONNECT when the immediately previous
         MQTT event was not DISCONNECT.
      The anomaly count is normalized by total MQTT events in the window.
    - `missing_handshake_ratio_lite` greedily matches eligible uplink CONNECT
      events to the next downlink CONNACK within a 1-second local neighborhood.
      CONNECTs too close to the window boundary are excluded from the denominator
      to avoid penalizing boundary-crossing handshakes.
    """

    ordered_events = _normalize_events(events)
    mqtt_event_count = len(ordered_events)
    if mqtt_event_count == 0:
        return SemanticLiteResult(
            reconnect_frequency=0.0,
            order_anomaly_ratio_lite=0.0,
            missing_handshake_ratio_lite=0.0,
            mqtt_event_count=0,
            connect_count=0,
            eligible_connect_count=0,
            sparse_semantic_inputs=True,
            orphan_connack_count=0,
            activity_before_connect_count=0,
            repeated_connect_jump_count=0,
        )

    first_timestamp = ordered_events[0][0]
    window_end = first_timestamp + pd.Timedelta(seconds=window_duration_seconds)
    connect_indices = [
        index for index, (_, message_type, _) in enumerate(ordered_events) if message_type == CONNECT
    ]
    connect_count = len(connect_indices)
    repeated_connects = max(connect_count - 1, 0)
    reconnect_frequency = repeated_connects / float(window_duration_seconds)

    first_connect_index = connect_indices[0] if connect_indices else None
    activity_before_connect_count = 0
    orphan_connack_count = 0
    repeated_connect_jump_count = 0

    if first_connect_index is not None:
        for index, (_, message_type, _) in enumerate(ordered_events[:first_connect_index]):
            if message_type in ACTIVITY_TYPES:
                activity_before_connect_count += 1
            elif message_type == CONNACK:
                orphan_connack_count += 1

        for connect_index in connect_indices[1:]:
            previous_message_type = ordered_events[connect_index - 1][1]
            if previous_message_type != DISCONNECT:
                repeated_connect_jump_count += 1

    anomaly_count = (
        activity_before_connect_count
        + orphan_connack_count
        + repeated_connect_jump_count
    )
    order_anomaly_ratio_lite = safe_divide(anomaly_count, mqtt_event_count)

    pending_connacks = [
        (timestamp, direction)
        for timestamp, message_type, direction in ordered_events
        if message_type == CONNACK
    ]
    connack_index = 0
    eligible_connect_count = 0
    matched_connect_count = 0
    for timestamp, message_type, direction in ordered_events:
        if message_type != CONNECT or direction != "uplink":
            continue
        if (window_end - timestamp).total_seconds() < handshake_timeout_seconds:
            continue

        eligible_connect_count += 1
        while connack_index < len(pending_connacks):
            connack_timestamp, connack_direction = pending_connacks[connack_index]
            if connack_timestamp < timestamp:
                connack_index += 1
                continue
            if connack_direction != "downlink":
                connack_index += 1
                continue
            if (connack_timestamp - timestamp).total_seconds() <= handshake_timeout_seconds:
                matched_connect_count += 1
                connack_index += 1
            break

    unmatched_connect_count = max(eligible_connect_count - matched_connect_count, 0)
    missing_handshake_ratio_lite = safe_divide(
        unmatched_connect_count,
        eligible_connect_count,
    )

    return SemanticLiteResult(
        reconnect_frequency=reconnect_frequency,
        order_anomaly_ratio_lite=order_anomaly_ratio_lite,
        missing_handshake_ratio_lite=missing_handshake_ratio_lite,
        mqtt_event_count=mqtt_event_count,
        connect_count=connect_count,
        eligible_connect_count=eligible_connect_count,
        sparse_semantic_inputs=mqtt_event_count < 2 or eligible_connect_count == 0,
        orphan_connack_count=orphan_connack_count,
        activity_before_connect_count=activity_before_connect_count,
        repeated_connect_jump_count=repeated_connect_jump_count,
    )
