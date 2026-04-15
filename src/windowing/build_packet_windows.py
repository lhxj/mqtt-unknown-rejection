"""Build frozen-scope 5-second broker-facing packet windows."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import numpy as np
import pandas as pd

from src.features.semantic_lite import SEMANTIC_LITE_FEATURES, compute_semantic_lite_features
from src.features.stats_packet import PACKET_STAT_FEATURES, PacketStatsAccumulator
from src.loaders.packet_loader import PacketLoader
from src.windowing.common import (
    append_feature_coverage_rows,
    ensure_directory,
    load_yaml_config,
    parse_packet_timestamps,
    safe_divide,
    window_id_from_parts,
    write_text,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
WINDOW_OUTPUT_DIR = REPO_ROOT / "data" / "interim" / "windows" / "packet"
WINDOWING_LOG_PATH = REPO_ROOT / "outputs" / "logs" / "windowing_sanity.log"
PACKET_FEATURE_LOG_PATH = REPO_ROOT / "outputs" / "logs" / "packet_feature_sanity.log"
SEMANTIC_LOG_PATH = REPO_ROOT / "outputs" / "logs" / "semantic_lite_sanity.log"
WINDOW_COUNT_TABLE_PATH = REPO_ROOT / "outputs" / "tables" / "tab_window_counts.csv"
FEATURE_COVERAGE_PATH = REPO_ROOT / "outputs" / "tables" / "tab_feature_coverage.csv"
WINDOWING_AUDIT_PATH = REPO_ROOT / "reports" / "windowing_audit.md"
SEMANTIC_AUDIT_PATH = REPO_ROOT / "reports" / "semantic_lite_audit.md"

REQUIRED_PACKET_COLUMNS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "ip_len",
    "tcp_flag_ack",
    "tcp_flag_syn",
    "tcp_flag_fin",
    "tcp_flag_reset",
    "tcp_flag_push",
    "mqtt_messagetype",
    "mqtt_messagelength",
    "is_attack",
)

KEY_COLUMNS = ("peer_ip", "peer_port", "window_start_5s")
FINAL_WINDOW_COLUMNS = (
    "window_id",
    "scenario",
    "family",
    "known_label",
    "attack_binary_label",
    "unknown_capable",
    "source_pool",
    "broker_ip",
    "peer_ip",
    "peer_port",
    "window_start_5s",
    "window_end_5s",
    "has_mqtt_packets",
    *PACKET_STAT_FEATURES,
    *SEMANTIC_LITE_FEATURES,
    "semantic_mqtt_event_count",
    "semantic_connect_count",
    "semantic_eligible_connect_count",
    "semantic_sparse_inputs",
    "semantic_orphan_connack_count",
    "semantic_activity_before_connect_count",
    "semantic_repeated_connect_jump_count",
    "packet_out_of_order_boundary_count",
)


@dataclass
class WindowAccumulator:
    """State for one broker-facing endpoint window."""

    scenario: str
    family: str
    broker_ip: str
    peer_ip: str
    peer_port: int
    window_start_5s: pd.Timestamp
    source_pool: str
    attack_binary_label: int
    known_label: str
    unknown_capable: bool
    packet_stats: PacketStatsAccumulator = field(default_factory=PacketStatsAccumulator)
    mqtt_events: list[tuple[pd.Timestamp, int, str]] = field(default_factory=list)

    def as_row(self, *, window_seconds: int) -> dict[str, Any]:
        """Finalize the window as one tabular output row."""

        semantic = compute_semantic_lite_features(
            self.mqtt_events,
            window_duration_seconds=float(window_seconds),
        )
        packet_features = self.packet_stats.finalize()
        row: dict[str, Any] = {
            "window_id": window_id_from_parts(
                self.broker_ip,
                self.peer_ip,
                self.peer_port,
                self.window_start_5s,
            ),
            "scenario": self.scenario,
            "family": self.family,
            "known_label": self.known_label,
            "attack_binary_label": self.attack_binary_label,
            "unknown_capable": self.unknown_capable,
            "source_pool": self.source_pool,
            "broker_ip": self.broker_ip,
            "peer_ip": self.peer_ip,
            "peer_port": self.peer_port,
            "window_start_5s": self.window_start_5s,
            "window_end_5s": self.window_start_5s + pd.Timedelta(seconds=window_seconds),
            "has_mqtt_packets": packet_features["mqtt_pkt_count"] > 0,
        }
        row.update(packet_features)
        row.update(semantic.as_feature_dict())
        row.update(semantic.as_metadata_dict())
        row["packet_out_of_order_boundary_count"] = self.packet_stats.out_of_order_boundaries
        return row


@dataclass
class AggregationPool:
    """Per-pool aggregation state and scenario-level counters."""

    scenario: str
    family: str
    source_pool: str
    broker_ip: str
    attack_binary_label: int
    known_label: str
    unknown_capable: bool
    windows: dict[tuple[str, int, pd.Timestamp], WindowAccumulator] = field(default_factory=dict)
    last_timestamp_by_key: dict[tuple[str, int, pd.Timestamp], pd.Timestamp] = field(default_factory=dict)
    row_count: int = 0

    def get_or_create(self, key: tuple[str, int, pd.Timestamp]) -> WindowAccumulator:
        """Fetch or create one window accumulator."""

        if key not in self.windows:
            peer_ip, peer_port, window_start = key
            self.windows[key] = WindowAccumulator(
                scenario=self.scenario,
                family=self.family,
                broker_ip=self.broker_ip,
                peer_ip=peer_ip,
                peer_port=peer_port,
                window_start_5s=window_start,
                source_pool=self.source_pool,
                attack_binary_label=self.attack_binary_label,
                known_label=self.known_label,
                unknown_capable=self.unknown_capable,
            )
        return self.windows[key]


@dataclass
class ScenarioStats:
    """Scenario-level counters for logs and audits."""

    scenario: str
    raw_rows: int = 0
    invalid_timestamp_rows: int = 0
    non_broker_rows: int = 0
    broker_ambiguity_rows: int = 0
    normal_candidate_rows: int = 0
    attack_candidate_rows: int = 0
    normal_candidate_rows_from_attack_file: int = 0
    unexpected_attack_rows_in_normal_file: int = 0
    boundary_out_of_order_windows: int = 0


def _require_parquet_support() -> None:
    """Ensure a parquet engine is installed before building outputs."""

    if importlib.util.find_spec("pyarrow") is None:
        raise RuntimeError(
            "pyarrow is required to write parquet outputs for Phase 2. "
            "Install it before running src/windowing/build_packet_windows.py."
        )


def _output_path_for_pool(scenario: str, pool_name: str) -> Path:
    """Return the output parquet path for one window pool."""

    if pool_name == "main":
        if scenario == "normal":
            return WINDOW_OUTPUT_DIR / "normal_windows.parquet"
        return WINDOW_OUTPUT_DIR / f"{scenario}_attack_windows.parquet"
    return WINDOW_OUTPUT_DIR / f"{scenario}_benign_robustness_windows.parquet"


def _coerce_numeric(frame: pd.DataFrame, column: str) -> pd.Series:
    """Convert a column to numeric values without raising."""

    return pd.to_numeric(frame[column], errors="coerce")


def _aggregate_subset(
    subset: pd.DataFrame,
    *,
    pool: AggregationPool,
) -> None:
    """Aggregate one chunk subset into merge-friendly window accumulators."""

    if subset.empty:
        return

    working = subset.sort_values(list(KEY_COLUMNS) + ["timestamp_dt"], kind="stable").copy()
    working["ip_len_num"] = _coerce_numeric(working, "ip_len")
    working["ip_len_valid"] = working["ip_len_num"].notna().astype("int64")
    working["ip_len_num"] = working["ip_len_num"].fillna(0.0)
    working["ip_len_sq"] = working["ip_len_num"] * working["ip_len_num"]

    for flag_column in [
        "tcp_flag_ack",
        "tcp_flag_syn",
        "tcp_flag_fin",
        "tcp_flag_reset",
        "tcp_flag_push",
    ]:
        working[flag_column] = _coerce_numeric(working, flag_column).fillna(0.0)

    working["mqtt_messagetype_num"] = _coerce_numeric(working, "mqtt_messagetype")
    working["mqtt_present"] = working["mqtt_messagetype_num"].notna().astype("int64")
    working["mqtt_messagelength_num"] = _coerce_numeric(working, "mqtt_messagelength")
    working["mqtt_messagelength_valid"] = working["mqtt_messagelength_num"].notna().astype("int64")
    working["mqtt_messagelength_num"] = working["mqtt_messagelength_num"].fillna(0.0)
    working["mqtt_msglen_sq"] = (
        working["mqtt_messagelength_num"] * working["mqtt_messagelength_num"]
    )

    working["uplink_pkt_indicator"] = working["direction"].eq("uplink").astype("int64")
    working["downlink_pkt_indicator"] = working["direction"].eq("downlink").astype("int64")
    working["uplink_byte_count"] = working["ip_len_num"] * working["uplink_pkt_indicator"]
    working["downlink_byte_count"] = working["ip_len_num"] * working["downlink_pkt_indicator"]

    working["iat_seconds"] = (
        working.groupby(list(KEY_COLUMNS), sort=False)["timestamp_dt"]
        .diff()
        .dt.total_seconds()
    )
    working["iat_sq"] = working["iat_seconds"] * working["iat_seconds"]

    group = working.groupby(list(KEY_COLUMNS), sort=False, dropna=False)
    partial = group.agg(
        packet_count=("timestamp_dt", "size"),
        byte_sum=("ip_len_num", "sum"),
        pkt_len_count=("ip_len_valid", "sum"),
        pkt_len_sum=("ip_len_num", "sum"),
        pkt_len_sumsq=("ip_len_sq", "sum"),
        pkt_len_min=("ip_len_num", "min"),
        pkt_len_max=("ip_len_num", "max"),
        tcp_ack_count=("tcp_flag_ack", "sum"),
        tcp_syn_count=("tcp_flag_syn", "sum"),
        tcp_fin_count=("tcp_flag_fin", "sum"),
        tcp_rst_count=("tcp_flag_reset", "sum"),
        tcp_psh_count=("tcp_flag_push", "sum"),
        mqtt_pkt_count=("mqtt_present", "sum"),
        mqtt_msglen_count=("mqtt_messagelength_valid", "sum"),
        mqtt_msglen_sum=("mqtt_messagelength_num", "sum"),
        mqtt_msglen_sumsq=("mqtt_msglen_sq", "sum"),
        uplink_pkt_count=("uplink_pkt_indicator", "sum"),
        downlink_pkt_count=("downlink_pkt_indicator", "sum"),
        uplink_byte_count=("uplink_byte_count", "sum"),
        downlink_byte_count=("downlink_byte_count", "sum"),
        first_timestamp=("timestamp_dt", "first"),
        last_timestamp=("timestamp_dt", "last"),
    ).reset_index()

    iat_working = working.loc[working["iat_seconds"].notna()].copy()
    if iat_working.empty:
        partial["iat_count"] = 0
        partial["iat_sum"] = 0.0
        partial["iat_sumsq"] = 0.0
        partial["iat_min"] = float("inf")
        partial["iat_max"] = float("-inf")
    else:
        iat_partial = (
            iat_working.groupby(list(KEY_COLUMNS), sort=False, dropna=False)
            .agg(
                iat_count=("iat_seconds", "size"),
                iat_sum=("iat_seconds", "sum"),
                iat_sumsq=("iat_sq", "sum"),
                iat_min=("iat_seconds", "min"),
                iat_max=("iat_seconds", "max"),
            )
            .reset_index()
        )
        partial = partial.merge(iat_partial, on=list(KEY_COLUMNS), how="left")
        partial["iat_count"] = partial["iat_count"].fillna(0).astype("int64")
        partial["iat_sum"] = partial["iat_sum"].fillna(0.0)
        partial["iat_sumsq"] = partial["iat_sumsq"].fillna(0.0)
        partial["iat_min"] = partial["iat_min"].fillna(float("inf"))
        partial["iat_max"] = partial["iat_max"].fillna(float("-inf"))

    for row in partial.itertuples(index=False):
        key = (str(row.peer_ip), int(row.peer_port), row.window_start_5s)
        accumulator = pool.get_or_create(key)
        previous_last = pool.last_timestamp_by_key.get(key)
        if previous_last is not None:
            boundary_delta = (row.first_timestamp - previous_last).total_seconds()
            accumulator.packet_stats.add_iat_boundary(boundary_delta)
        accumulator.packet_stats.merge_partial(
            {
                "packet_count": int(row.packet_count),
                "byte_sum": float(row.byte_sum),
                "pkt_len_count": int(row.pkt_len_count),
                "pkt_len_sum": float(row.pkt_len_sum),
                "pkt_len_sumsq": float(row.pkt_len_sumsq),
                "pkt_len_min": float(row.pkt_len_min),
                "pkt_len_max": float(row.pkt_len_max),
                "iat_count": int(row.iat_count),
                "iat_sum": float(row.iat_sum),
                "iat_sumsq": float(row.iat_sumsq),
                "iat_min": float(row.iat_min),
                "iat_max": float(row.iat_max),
                "tcp_ack_count": int(round(row.tcp_ack_count)),
                "tcp_syn_count": int(round(row.tcp_syn_count)),
                "tcp_fin_count": int(round(row.tcp_fin_count)),
                "tcp_rst_count": int(round(row.tcp_rst_count)),
                "tcp_psh_count": int(round(row.tcp_psh_count)),
                "mqtt_pkt_count": int(row.mqtt_pkt_count),
                "mqtt_msglen_count": int(row.mqtt_msglen_count),
                "mqtt_msglen_sum": float(row.mqtt_msglen_sum),
                "mqtt_msglen_sumsq": float(row.mqtt_msglen_sumsq),
                "uplink_pkt_count": int(row.uplink_pkt_count),
                "downlink_pkt_count": int(row.downlink_pkt_count),
                "uplink_byte_count": float(row.uplink_byte_count),
                "downlink_byte_count": float(row.downlink_byte_count),
                "last_timestamp": row.last_timestamp,
            }
        )
        if previous_last is None or row.last_timestamp > previous_last:
            pool.last_timestamp_by_key[key] = row.last_timestamp

    mqtt_counts = (
        working.loc[working["mqtt_messagetype_num"].notna()]
        .groupby(list(KEY_COLUMNS) + ["mqtt_messagetype_num"], sort=False, dropna=False)
        .size()
    )
    for (peer_ip, peer_port, window_start, message_type), count in mqtt_counts.items():
        key = (str(peer_ip), int(peer_port), window_start)
        accumulator = pool.get_or_create(key)
        accumulator.packet_stats.mqtt_msgtype_counts[int(message_type)] += int(count)

    mqtt_events = working.loc[
        working["mqtt_messagetype_num"].notna(),
        list(KEY_COLUMNS) + ["timestamp_dt", "mqtt_messagetype_num", "direction"],
    ]
    for event in mqtt_events.itertuples(index=False):
        key = (str(event.peer_ip), int(event.peer_port), event.window_start_5s)
        accumulator = pool.get_or_create(key)
        accumulator.mqtt_events.append(
            (event.timestamp_dt, int(event.mqtt_messagetype_num), str(event.direction))
        )

    pool.row_count += len(working)


def _scenario_pools(
    scenario: str,
    *,
    broker_ip: str,
) -> tuple[AggregationPool, AggregationPool]:
    """Build the main and robustness pools for one scenario."""

    if scenario == "normal":
        main_pool = AggregationPool(
            scenario=scenario,
            family="normal",
            source_pool="main",
            broker_ip=broker_ip,
            attack_binary_label=0,
            known_label="normal",
            unknown_capable=False,
        )
    else:
        main_pool = AggregationPool(
            scenario=scenario,
            family=scenario,
            source_pool="main",
            broker_ip=broker_ip,
            attack_binary_label=1,
            known_label=scenario,
            unknown_capable=True,
        )

    robustness_pool = AggregationPool(
        scenario=scenario,
        family="normal",
        source_pool="robustness_benign_attack_rows",
        broker_ip=broker_ip,
        attack_binary_label=0,
        known_label="normal",
        unknown_capable=False,
    )
    return main_pool, robustness_pool


def _finalize_pool(pool: AggregationPool, *, window_seconds: int) -> pd.DataFrame:
    """Convert one aggregation pool into a final DataFrame."""

    rows = [window.as_row(window_seconds=window_seconds) for window in pool.windows.values()]
    if not rows:
        return pd.DataFrame(columns=list(FINAL_WINDOW_COLUMNS))

    frame = pd.DataFrame(rows)
    return frame.sort_values(
        by=["window_start_5s", "peer_ip", "peer_port"],
        kind="stable",
    ).reset_index(drop=True)


def _coverage_rows_for_frame(frame: pd.DataFrame) -> list[dict[str, Any]]:
    """Build coverage rows for packet stats and semantic-lite features."""

    rows: list[dict[str, Any]] = []
    for feature_name in PACKET_STAT_FEATURES + SEMANTIC_LITE_FEATURES:
        series = frame[feature_name]
        is_semantic = feature_name in SEMANTIC_LITE_FEATURES
        notes = ""
        if is_semantic:
            notes = (
                "Raw semantic-lite feature. Fold-local minmax normalization is "
                "deferred to Phase 3 to avoid leakage."
            )
        elif feature_name in {"direction_pkt_ratio", "direction_byte_ratio"}:
            notes = "Computed as uplink/downlink with denominator clipped at 1."

        rows.append(
            {
                "feature_name": feature_name,
                "source_dataset": "mqtt_iot_ids2020",
                "source_granularity": "packet_window",
                "non_null_rate": round(float(series.notna().mean()), 6),
                "non_zero_rate": round(float(series.fillna(0).ne(0).mean()), 6),
                "constant_flag": bool(series.fillna(0).nunique(dropna=False) <= 1),
                "allowed_for_classifier": not is_semantic,
                "allowed_for_gate": is_semantic,
                "notes": notes,
            }
        )
    return rows


def _write_windowing_audit(
    *,
    scenario_summary: pd.DataFrame,
    scenario_stats: dict[str, ScenarioStats],
) -> None:
    """Write the required markdown audit for packet windowing."""

    summary_text = scenario_summary.to_string(index=False)
    lines = [
        "# Windowing Audit",
        "",
        "## Exact Window Key",
        "",
        "`{broker_ip, peer_ip, peer_port, window_start_5s}`",
        "",
        "## Broker-Facing Rule",
        "",
        "Broker-facing direction was determined with the confirmed broker IP `192.168.1.7`.",
        "Rows where `dst_ip == broker_ip` were treated as uplink; rows where `src_ip == broker_ip` were treated as downlink.",
        "Rows involving neither endpoint as the broker were excluded from broker-facing window construction.",
        "Rows where both endpoints matched the broker IP were logged as broker-facing ambiguity and excluded.",
        "",
        "## Benign Rows Inside Attack Files",
        "",
        "Main attack-window tables use only `is_attack == 1` rows from attack-family CSVs.",
        "Benign broker-facing rows inside attack CSVs were separated into optional robustness pools and were not merged into the main benchmark tables.",
        "",
        "## Fallback Logic",
        "",
        "The fallback window key from `spec_v1.md` was not used because the broker IP was already confirmed and stable.",
        "",
        "## Scenario-Level Window Counts",
        "",
        "```text",
        summary_text,
        "```",
        "",
        "## Ambiguous Cases",
        "",
    ]
    for scenario, stats in scenario_stats.items():
        lines.extend(
            [
                f"- `{scenario}`: invalid timestamps={stats.invalid_timestamp_rows}, "
                f"non-broker rows={stats.non_broker_rows}, "
                f"broker ambiguities={stats.broker_ambiguity_rows}, "
                f"unexpected attack rows in normal file={stats.unexpected_attack_rows_in_normal_file}, "
                f"out-of-order packet boundaries={stats.boundary_out_of_order_windows}",
            ]
        )

    write_text(WINDOWING_AUDIT_PATH, "\n".join(lines) + "\n")


def _write_semantic_audit(
    *,
    full_frame: pd.DataFrame,
    feature_coverage_rows: list[dict[str, Any]],
) -> None:
    """Write the required markdown audit for semantic-lite features."""

    semantic_rows = [
        row for row in feature_coverage_rows if row["feature_name"] in SEMANTIC_LITE_FEATURES
    ]
    sparsity_threshold = 0.01
    viable = [
        row["feature_name"]
        for row in semantic_rows
        if row["non_zero_rate"] >= sparsity_threshold and not row["constant_flag"]
    ]
    weak = [
        row["feature_name"]
        for row in semantic_rows
        if row["feature_name"] not in viable
    ]

    scenario_lines = []
    for scenario, scenario_frame in full_frame.groupby("scenario", sort=False):
        for feature_name in SEMANTIC_LITE_FEATURES:
            scenario_lines.append(
                f"- `{scenario}` / `{feature_name}`: "
                f"non-zero rate={scenario_frame[feature_name].fillna(0).ne(0).mean():.4f}, "
                f"mean={scenario_frame[feature_name].fillna(0).mean():.6f}"
            )

    lines = [
        "# Semantic-Lite Audit",
        "",
        "## Exact Formulas Used",
        "",
        "- `reconnect_frequency`: `max(connect_count - 1, 0) / 5.0` where CONNECT-like behavior is MQTT message type `1`.",
        "- `order_anomaly_ratio_lite`: `(activity_before_first_connect + connack_before_first_connect + repeated_connect_without_disconnect) / mqtt_event_count`.",
        "- `missing_handshake_ratio_lite`: unmatched eligible uplink CONNECT events divided by eligible CONNECT events, where eligibility requires at least 1 second of remaining window time and matching looks for the next downlink CONNACK within 1 second.",
        "",
        "## Message-Type Assumptions",
        "",
        "- CONNECT is MQTT message type `1`.",
        "- CONNACK is MQTT message type `2`.",
        "- DISCONNECT is MQTT message type `14`.",
        "- Activity types are the coarse MQTT control/business range `3..14` excluding CONNECT and CONNACK.",
        "- Windows with no MQTT packets or no eligible CONNECTs remain valid samples, but their semantic-lite features are expected to be zero and are logged as sparse inputs.",
        "",
        "## Sparsity Observations",
        "",
        f"- Total windows with sparse semantic inputs: {int(full_frame['semantic_sparse_inputs'].sum())}",
        f"- Total windows with no MQTT packets: {int(full_frame['has_mqtt_packets'].eq(False).sum())}",
        "",
        "## Scenario Detail",
        "",
        *scenario_lines,
        "",
        "## Phase 3 Viability",
        "",
        f"- Viable for Phase 3 gate training: {', '.join(viable) if viable else 'none'}",
        f"- Likely weak or too sparse: {', '.join(weak) if weak else 'none'}",
        "",
        "## Notes",
        "",
        "- Semantic-lite features stay on the gate path only; they are not marked as classifier inputs.",
        "- Fold-local minmax normalization is deferred to Phase 3 split-time processing to avoid test leakage.",
    ]
    write_text(SEMANTIC_AUDIT_PATH, "\n".join(lines) + "\n")


def build_packet_windows() -> dict[str, pd.DataFrame]:
    """Build the required packet-window outputs and sanity artifacts."""

    _require_parquet_support()
    data_config = load_yaml_config(REPO_ROOT / "configs" / "data.yaml")
    feature_config = load_yaml_config(REPO_ROOT / "configs" / "features.yaml")
    window_seconds = int(data_config["windowing"]["window_seconds"])
    broker_ip = str(data_config["windowing"]["broker_context"]["broker_ip"])

    ensure_directory(WINDOW_OUTPUT_DIR)
    ensure_directory(REPO_ROOT / "outputs" / "logs")
    ensure_directory(REPO_ROOT / "outputs" / "tables")
    ensure_directory(REPO_ROOT / "reports")

    loader = PacketLoader()
    scenario_outputs: dict[str, pd.DataFrame] = {}
    robustness_outputs: dict[str, pd.DataFrame] = {}
    scenario_stats: dict[str, ScenarioStats] = {}

    for scenario in loader.available_scenarios():
        main_pool, robustness_pool = _scenario_pools(scenario, broker_ip=broker_ip)
        stats = ScenarioStats(scenario=scenario)
        scenario_stats[scenario] = stats

        for chunk in loader.iter_scenario(
            scenario,
            columns=REQUIRED_PACKET_COLUMNS,
            chunksize=200_000,
        ):
            stats.raw_rows += len(chunk)
            parsed_timestamps = parse_packet_timestamps(chunk["timestamp"])
            invalid_timestamp_mask = parsed_timestamps.isna()
            stats.invalid_timestamp_rows += int(invalid_timestamp_mask.sum())
            if invalid_timestamp_mask.all():
                continue

            working = chunk.loc[~invalid_timestamp_mask].copy()
            working["timestamp_dt"] = parsed_timestamps.loc[~invalid_timestamp_mask]
            src_is_broker = working["src_ip"].eq(broker_ip)
            dst_is_broker = working["dst_ip"].eq(broker_ip)
            ambiguity_mask = src_is_broker & dst_is_broker
            stats.broker_ambiguity_rows += int(ambiguity_mask.sum())
            working = working.loc[~ambiguity_mask].copy()
            src_is_broker = working["src_ip"].eq(broker_ip)
            dst_is_broker = working["dst_ip"].eq(broker_ip)

            broker_facing_mask = src_is_broker ^ dst_is_broker
            stats.non_broker_rows += int((~broker_facing_mask).sum())
            working = working.loc[broker_facing_mask].copy()
            if working.empty:
                continue

            dst_is_broker = working["dst_ip"].eq(broker_ip)
            working["direction"] = np.where(dst_is_broker, "uplink", "downlink")
            working["peer_ip"] = np.where(dst_is_broker, working["src_ip"], working["dst_ip"])
            working["peer_port"] = np.where(dst_is_broker, working["src_port"], working["dst_port"])
            working["peer_port"] = pd.to_numeric(working["peer_port"], errors="coerce").astype("Int64")
            working = working.loc[working["peer_port"].notna()].copy()
            working["peer_port"] = working["peer_port"].astype(int)
            working["window_start_5s"] = working["timestamp_dt"].dt.floor(f"{window_seconds}s")

            is_attack = pd.to_numeric(working["is_attack"], errors="coerce").fillna(0).astype(int)
            if scenario == "normal":
                main_subset = working.loc[is_attack == 0].copy()
                stats.normal_candidate_rows += len(main_subset)
                unexpected_attack_rows = int((is_attack == 1).sum())
                stats.unexpected_attack_rows_in_normal_file += unexpected_attack_rows
                robustness_subset = working.iloc[0:0].copy()
            else:
                main_subset = working.loc[is_attack == 1].copy()
                robustness_subset = working.loc[is_attack == 0].copy()
                stats.attack_candidate_rows += len(main_subset)
                stats.normal_candidate_rows_from_attack_file += len(robustness_subset)

            _aggregate_subset(main_subset, pool=main_pool)
            _aggregate_subset(robustness_subset, pool=robustness_pool)

        main_frame = _finalize_pool(main_pool, window_seconds=window_seconds)
        robustness_frame = _finalize_pool(robustness_pool, window_seconds=window_seconds)
        scenario_outputs[scenario] = main_frame
        robustness_outputs[scenario] = robustness_frame

        stats.boundary_out_of_order_windows = int(
            main_frame.get("packet_out_of_order_boundary_count", pd.Series(dtype="int64")).sum()
            + robustness_frame.get("packet_out_of_order_boundary_count", pd.Series(dtype="int64")).sum()
        )

        main_output_path = _output_path_for_pool(scenario, "main")
        main_frame.to_parquet(main_output_path, index=False, engine="pyarrow")
        if not robustness_frame.empty:
            robustness_frame.to_parquet(
                _output_path_for_pool(scenario, "robustness"),
                index=False,
                engine="pyarrow",
            )

    non_empty_main_frames = [frame for frame in scenario_outputs.values() if not frame.empty]
    full_main_frame = (
        pd.concat(non_empty_main_frames, ignore_index=True)
        if non_empty_main_frames
        else pd.DataFrame(columns=list(FINAL_WINDOW_COLUMNS))
    )
    if not full_main_frame.empty:
        full_main_frame["has_mqtt_packets"] = full_main_frame["has_mqtt_packets"].astype(bool)
        full_main_frame["semantic_sparse_inputs"] = full_main_frame["semantic_sparse_inputs"].astype(bool)
    feature_coverage_rows = _coverage_rows_for_frame(full_main_frame)
    append_feature_coverage_rows(FEATURE_COVERAGE_PATH, feature_coverage_rows)

    window_count_rows: list[dict[str, Any]] = []
    for scenario, frame in scenario_outputs.items():
        robustness_frame = robustness_outputs[scenario]
        window_count_rows.append(
            {
                "scenario": scenario,
                "family": "normal" if scenario == "normal" else scenario,
                "total_windows": int(len(frame)),
                "mqtt_windows": int(frame["has_mqtt_packets"].sum()),
                "non_mqtt_windows": int((~frame["has_mqtt_packets"]).sum()),
                "attack_windows": int(frame["attack_binary_label"].sum()),
                "normal_windows": int((frame["attack_binary_label"] == 0).sum()),
                "dropped_windows": int(len(robustness_frame)),
            }
        )
    window_count_frame = pd.DataFrame(window_count_rows).sort_values(
        by=["scenario"],
        kind="stable",
    )
    window_count_frame.to_csv(WINDOW_COUNT_TABLE_PATH, index=False)

    packet_feature_rows = [
        row for row in feature_coverage_rows if row["feature_name"] in PACKET_STAT_FEATURES
    ]
    semantic_feature_rows = [
        row for row in feature_coverage_rows if row["feature_name"] in SEMANTIC_LITE_FEATURES
    ]
    constant_packet_features = [
        row["feature_name"] for row in packet_feature_rows if row["constant_flag"]
    ]
    all_zero_semantic = [
        row["feature_name"] for row in semantic_feature_rows if row["non_zero_rate"] == 0.0
    ]

    windowing_lines = ["Packet windowing sanity summary", ""]
    for scenario, stats in scenario_stats.items():
        frame = scenario_outputs[scenario]
        robustness_frame = robustness_outputs[scenario]
        windowing_lines.extend(
            [
                f"[{scenario}]",
                f"raw_rows={stats.raw_rows}",
                f"invalid_timestamp_rows={stats.invalid_timestamp_rows}",
                f"non_broker_rows={stats.non_broker_rows}",
                f"broker_ambiguity_rows={stats.broker_ambiguity_rows}",
                f"main_windows={len(frame)}",
                f"robustness_windows={len(robustness_frame)}",
                f"main_rows_used={len(frame) and int(frame['num_pkts_total'].sum()) or 0}",
                f"windows_with_no_mqtt={int((~frame['has_mqtt_packets']).sum())}",
                f"sparse_semantic_windows={int(frame['semantic_sparse_inputs'].sum())}",
                f"boundary_out_of_order_windows={stats.boundary_out_of_order_windows}",
                "",
            ]
        )
    write_text(WINDOWING_LOG_PATH, "\n".join(windowing_lines).strip() + "\n")

    packet_feature_lines = [
        "Packet feature sanity summary",
        "",
        f"packet_feature_count={len(packet_feature_rows)}",
        f"constant_packet_features={', '.join(constant_packet_features) if constant_packet_features else 'none'}",
        "",
    ]
    for row in packet_feature_rows:
        packet_feature_lines.append(
            f"{row['feature_name']}: non_null_rate={row['non_null_rate']}, "
            f"non_zero_rate={row['non_zero_rate']}, constant={row['constant_flag']}"
        )
    write_text(PACKET_FEATURE_LOG_PATH, "\n".join(packet_feature_lines) + "\n")

    semantic_lines = [
        "Semantic-lite sanity summary",
        "",
        f"semantic_feature_count={len(semantic_feature_rows)}",
        f"all_zero_semantic_features={', '.join(all_zero_semantic) if all_zero_semantic else 'none'}",
        f"sparse_semantic_windows={int(full_main_frame['semantic_sparse_inputs'].sum())}",
        "",
    ]
    for scenario, frame in full_main_frame.groupby("scenario", sort=False):
        semantic_lines.append(f"[{scenario}]")
        for feature_name in SEMANTIC_LITE_FEATURES:
            semantic_lines.append(
                f"{feature_name}: non_zero_rate={frame[feature_name].fillna(0).ne(0).mean():.6f}, "
                f"non_null_rate={frame[feature_name].notna().mean():.6f}, "
                f"mean={frame[feature_name].fillna(0).mean():.6f}"
            )
        semantic_lines.append(
            f"sparse_semantic_windows={int(frame['semantic_sparse_inputs'].sum())}"
        )
        semantic_lines.append("")
    write_text(SEMANTIC_LOG_PATH, "\n".join(semantic_lines).rstrip() + "\n")

    _write_windowing_audit(
        scenario_summary=window_count_frame,
        scenario_stats=scenario_stats,
    )
    _write_semantic_audit(
        full_frame=full_main_frame,
        feature_coverage_rows=feature_coverage_rows,
    )

    return scenario_outputs


def main() -> None:
    """CLI entry point for packet window construction."""

    build_packet_windows()


if __name__ == "__main__":
    main()
