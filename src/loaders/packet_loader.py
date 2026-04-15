"""Scenario-aware loader for MQTT-IoT-IDS2020 packet features."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Sequence

import pandas as pd

from src.loaders.common import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_DATA_CONFIG_PATH,
    PrimaryDatasetConfig,
    iter_consistent_csv,
    load_consistent_csv,
    load_primary_dataset_config,
    resolve_packet_csv_path,
)


PACKET_COLUMNS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "ttl",
    "ip_len",
    "ip_flag_df",
    "ip_flag_mf",
    "ip_flag_rb",
    "src_port",
    "dst_port",
    "tcp_flag_res",
    "tcp_flag_ns",
    "tcp_flag_cwr",
    "tcp_flag_ecn",
    "tcp_flag_urg",
    "tcp_flag_ack",
    "tcp_flag_push",
    "tcp_flag_reset",
    "tcp_flag_syn",
    "tcp_flag_fin",
    "mqtt_messagetype",
    "mqtt_messagelength",
    "mqtt_flag_uname",
    "mqtt_flag_passwd",
    "mqtt_flag_retain",
    "mqtt_flag_qos",
    "mqtt_flag_willflag",
    "mqtt_flag_clean",
    "mqtt_flag_reserved",
    "is_attack",
)

PACKET_STRING_COLUMNS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
)

PACKET_NUMERIC_COLUMNS = tuple(
    column for column in PACKET_COLUMNS if column not in PACKET_STRING_COLUMNS
)

PACKET_REQUIRED_COLUMNS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "is_attack",
)

PACKET_SEMANTIC_COLUMNS = (
    "mqtt_messagetype",
    "mqtt_messagelength",
    "mqtt_flag_clean",
    "mqtt_flag_qos",
    "mqtt_flag_uname",
    "mqtt_flag_passwd",
    "mqtt_flag_willflag",
)


@dataclass
class PacketLoader:
    """Load packet CSVs by scenario without widening the frozen scope."""

    config_path: str | Path = DEFAULT_DATA_CONFIG_PATH
    default_chunksize: int = DEFAULT_CHUNK_SIZE
    config: PrimaryDatasetConfig = field(init=False)

    def __post_init__(self) -> None:
        self.config = load_primary_dataset_config(self.config_path)

    @property
    def expected_columns(self) -> tuple[str, ...]:
        return PACKET_COLUMNS

    @property
    def required_columns(self) -> tuple[str, ...]:
        return PACKET_REQUIRED_COLUMNS

    @property
    def semantic_columns(self) -> tuple[str, ...]:
        return PACKET_SEMANTIC_COLUMNS

    def available_scenarios(self) -> tuple[str, ...]:
        return tuple(sorted(self.config.scenario_files))

    def scenario_path(self, scenario: str) -> Path:
        return resolve_packet_csv_path(scenario, self.config)

    def iter_scenario(
        self,
        scenario: str,
        *,
        columns: Sequence[str] | None = None,
        chunksize: int | None = None,
        nrows: int | None = None,
    ) -> Iterator[pd.DataFrame]:
        """Yield cleaned packet chunks for a single scenario."""

        csv_path = self.scenario_path(scenario)
        yield from iter_consistent_csv(
            csv_path,
            expected_columns=self.expected_columns,
            string_columns=PACKET_STRING_COLUMNS,
            numeric_columns=PACKET_NUMERIC_COLUMNS,
            columns=columns,
            chunksize=chunksize or self.default_chunksize,
            nrows=nrows,
        )

    def load_scenario(
        self,
        scenario: str,
        *,
        columns: Sequence[str] | None = None,
        nrows: int | None = None,
        chunksize: int | None = None,
    ) -> pd.DataFrame | Iterator[pd.DataFrame]:
        """Load one scenario as a DataFrame or cleaned chunk iterator."""

        if chunksize is not None:
            return self.iter_scenario(
                scenario,
                columns=columns,
                chunksize=chunksize,
                nrows=nrows,
            )

        csv_path = self.scenario_path(scenario)
        return load_consistent_csv(
            csv_path,
            expected_columns=self.expected_columns,
            string_columns=PACKET_STRING_COLUMNS,
            numeric_columns=PACKET_NUMERIC_COLUMNS,
            columns=columns,
            nrows=nrows,
            chunksize=self.default_chunksize,
        )
