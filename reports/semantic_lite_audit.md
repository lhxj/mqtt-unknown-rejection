# Semantic-Lite Audit

## Exact Formulas Used

- `reconnect_frequency`: `max(connect_count - 1, 0) / 5.0` where CONNECT-like behavior is MQTT message type `1`.
- `order_anomaly_ratio_lite`: `(activity_before_first_connect + connack_before_first_connect + repeated_connect_without_disconnect) / mqtt_event_count`.
- `missing_handshake_ratio_lite`: unmatched eligible uplink CONNECT events divided by eligible CONNECT events, where eligibility requires at least 1 second of remaining window time and matching looks for the next downlink CONNACK within 1 second.

## Message-Type Assumptions

- CONNECT is MQTT message type `1`.
- CONNACK is MQTT message type `2`.
- DISCONNECT is MQTT message type `14`.
- Activity types are the coarse MQTT control/business range `3..14` excluding CONNECT and CONNACK.
- Windows with no MQTT packets or no eligible CONNECTs remain valid samples, but their semantic-lite features are expected to be zero and are logged as sparse inputs.

## Sparsity Observations

- Total windows with sparse semantic inputs: 395
- Total windows with no MQTT packets: 108

## Scenario Detail

- `normal` / `reconnect_frequency`: non-zero rate=0.0000, mean=0.000000
- `normal` / `order_anomaly_ratio_lite`: non-zero rate=0.0000, mean=0.000000
- `normal` / `missing_handshake_ratio_lite`: non-zero rate=0.0001, mean=0.000088
- `mqtt_bruteforce` / `reconnect_frequency`: non-zero rate=0.1399, mean=0.031046
- `mqtt_bruteforce` / `order_anomaly_ratio_lite`: non-zero rate=0.1399, mean=0.036193
- `mqtt_bruteforce` / `missing_handshake_ratio_lite`: non-zero rate=0.0000, mean=0.000026

## Phase 3 Viability

- Viable for Phase 3 gate training: reconnect_frequency, order_anomaly_ratio_lite
- Likely weak or too sparse: missing_handshake_ratio_lite

## Notes

- Semantic-lite features stay on the gate path only; they are not marked as classifier inputs.
- Fold-local minmax normalization is deferred to Phase 3 split-time processing to avoid test leakage.
