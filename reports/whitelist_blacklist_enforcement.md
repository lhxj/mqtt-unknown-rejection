# Whitelist / Blacklist Enforcement Report

Status: Phase 1 initial audit
Scope locked to `spec_v1.md`, `configs/data.yaml`, `configs/features.yaml`, `configs/split.yaml`, `configs/gate.yaml`, and `configs/edge.yaml`

## Raw Fields Found

- MQTT-IoT-IDS2020 `packet_features` exposes 31 raw columns.
- MQTT-IoT-IDS2020 `biflow_features` exposes 32 raw columns.
- MQTT_UAD exposes 67 raw columns shared by `DoS.csv`, `MitM.csv`, and `Intrusion.csv`.
- The union across the three schemas is 129 distinct raw columns.
- The field-level inventory used for enforcement is recorded in `outputs/tables/tab_field_whitelist_blacklist.csv`.

## Blacklisted Fields

- `configs/features.yaml` declares 21 blacklist entries.
- 18 blacklist entries are present in the current raw headers.
- 3 blacklist entries are config-only placeholders for derived metadata: `file_id`, `scenario_id`, `fold_id`.
- Blacklisted fields never enter the classifier matrix. This includes labels, raw IP/MAC identity, raw time/order signals, protocol identity, and scene/fold metadata.

Present blacklist fields:
`is_attack`, `type`, `src_ip`, `dst_ip`, `ip_src`, `ip_dst`, `ip.src`, `ip.dst`, `eth.src`, `eth.dst`, `timestamp`, `frame.time_epoch`, `frame.time_relative`, `frame.time_delta`, `frame.time_delta_displayed`, `frame.number`, `protocol`, `proto`

## Grouping-Only Fields

- All 15 grouping-only fields declared in `configs/features.yaml` are present in the raw schemas.
- These fields may be used only for grouping, broker-facing window construction, or auxiliary sanity checks.
- They remain outside the classifier matrix even when they overlap with raw packet window context or auxiliary semantic fields.

Grouping-only fields:
`src_ip`, `dst_ip`, `src_port`, `dst_port`, `ip_src`, `ip_dst`, `prt_src`, `prt_dst`, `ip.src`, `ip.dst`, `tcp.srcport`, `tcp.dstport`, `timestamp`, `frame.time_epoch`, `mqtt.clientid`

## Statistical Fields

Packet-window raw inputs allowed for the statistical extraction path:
`ip_len`, `mqtt_messagelength`, `tcp_flag_ack`, `tcp_flag_push`, `tcp_flag_reset`, `tcp_flag_syn`, `tcp_flag_fin`, `mqtt_messagetype`

Packet-window derived statistical features frozen for later extraction:
`num_pkts_total`, `num_bytes_total`, `mean_pkt_len`, `std_pkt_len`, `min_pkt_len`, `max_pkt_len`, `mean_iat`, `std_iat`, `min_iat`, `max_iat`, `tcp_ack_count`, `tcp_syn_count`, `tcp_fin_count`, `tcp_rst_count`, `tcp_psh_count`, `mqtt_pkt_count`, `mqtt_pkt_ratio`, `mqtt_msgtype_entropy`, `mqtt_msglen_mean`, `mqtt_msglen_std`, `uplink_pkt_count`, `downlink_pkt_count`, `uplink_byte_count`, `downlink_byte_count`, `direction_pkt_ratio`, `direction_byte_ratio`

Biflow raw statistical fields allowed for the baseline path:
`fwd_num_pkts`, `bwd_num_pkts`, `fwd_num_bytes`, `bwd_num_bytes`, `fwd_mean_iat`, `bwd_mean_iat`, `fwd_std_iat`, `bwd_std_iat`, `fwd_min_iat`, `bwd_min_iat`, `fwd_max_iat`, `bwd_max_iat`, `fwd_mean_pkt_len`, `bwd_mean_pkt_len`, `fwd_std_pkt_len`, `bwd_std_pkt_len`, `fwd_min_pkt_len`, `bwd_min_pkt_len`, `fwd_max_pkt_len`, `bwd_max_pkt_len`, `fwd_num_psh_flags`, `bwd_num_psh_flags`, `fwd_num_rst_flags`, `bwd_num_rst_flags`, `fwd_num_urg_flags`, `bwd_num_urg_flags`

## Semantic-lite Fields

Primary semantic-lite raw inputs allowed only in the semantic extraction path:
`mqtt_messagetype`, `mqtt_messagelength`, `mqtt_flag_clean`, `mqtt_flag_qos`, `mqtt_flag_uname`, `mqtt_flag_passwd`, `mqtt_flag_willflag`

Auxiliary MQTT_UAD semantic raw inputs:
`mqtt.msgtype`, `mqtt.qos`, `mqtt.topic`, `mqtt.kalive`, `mqtt.msgid`, `mqtt.clientid`, `mqtt.conflag.cleansess`, `mqtt.conflag.passwd`, `mqtt.conflag.qos`, `mqtt.conflag.uname`, `mqtt.conflag.willflag`, `mqtt.conack.flags`, `mqtt.conack.flags.sp`, `mqtt.conack.val`

Frozen semantic features:
`reconnect_frequency`, `order_anomaly_ratio_lite`, `missing_handshake_ratio_lite`

Auxiliary-only or postponed semantic features:
`qos_mismatch_ratio_aux`, `keepalive_violation_count`

Policy enforcement:
- `classifier_uses_semantic_features: false`
- `gate_uses_semantic_features: true`
- No semantic raw field was promoted into the classifier matrix during Phase 1.

## Ambiguities and Missing Expected Columns

- No configured packet, biflow, or MQTT_UAD semantic input is missing from the expected datasets.
- 52 raw fields are present in the observed schemas but are not explicitly categorized by `configs/features.yaml`.
- Packet-side uncategorized fields relevant to the main benchmark are:
  `ttl`, `ip_flag_df`, `ip_flag_mf`, `ip_flag_rb`, `tcp_flag_res`, `tcp_flag_ns`, `tcp_flag_cwr`, `tcp_flag_ecn`, `tcp_flag_urg`, `mqtt_flag_retain`, `mqtt_flag_reserved`
- These packet-side uncategorized fields remain loader-visible but are held out of the classifier and semantic paths until explicitly whitelisted.
- The remaining uncategorized fields belong to MQTT_UAD frame/payload metadata such as `frame.*`, `mqtt.msg`, payload-length columns, and other auxiliary capture fields. They also stay outside the classifier by default.
- Embedded duplicate header rows were found in raw packet CSVs (`normal=1`, `sparta=20`, `mqtt_bruteforce=10`). The packet loader removes them before schema coercion.

## Phase 1 Decision

- Blacklist enforcement is viable with the current schemas.
- Grouping-only fields are sufficient for later 5-second broker-facing window construction.
- Statistical and semantic-lite raw inputs required by the frozen configs are present.
- No scope expansion was introduced in Phase 1.
