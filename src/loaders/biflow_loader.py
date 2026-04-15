"""Scenario-aware loader for MQTT-IoT-IDS2020 bi-flow features."""

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
    resolve_biflow_csv_path,
)


BIFLOW_COLUMNS = (
    "ip_src",
    "ip_dst",
    "prt_src",
    "prt_dst",
    "proto",
    "fwd_num_pkts",
    "bwd_num_pkts",
    "fwd_mean_iat",
    "bwd_mean_iat",
    "fwd_std_iat",
    "bwd_std_iat",
    "fwd_min_iat",
    "bwd_min_iat",
    "fwd_max_iat",
    "bwd_max_iat",
    "fwd_mean_pkt_len",
    "bwd_mean_pkt_len",
    "fwd_std_pkt_len",
    "bwd_std_pkt_len",
    "fwd_min_pkt_len",
    "bwd_min_pkt_len",
    "fwd_max_pkt_len",
    "bwd_max_pkt_len",
    "fwd_num_bytes",
    "bwd_num_bytes",
    "fwd_num_psh_flags",
    "bwd_num_psh_flags",
    "fwd_num_rst_flags",
    "bwd_num_rst_flags",
    "fwd_num_urg_flags",
    "bwd_num_urg_flags",
    "is_attack",
)

BIFLOW_STRING_COLUMNS = (
    "ip_src",
    "ip_dst",
)

BIFLOW_NUMERIC_COLUMNS = tuple(
    column for column in BIFLOW_COLUMNS if column not in BIFLOW_STRING_COLUMNS
)

BIFLOW_REQUIRED_COLUMNS = (
    "ip_src",
    "ip_dst",
    "prt_src",
    "prt_dst",
    "proto",
    "is_attack",
)


@dataclass
class BiflowLoader:
    """Load bi-flow CSVs by scenario without expanding past the frozen MVP."""

    config_path: str | Path = DEFAULT_DATA_CONFIG_PATH
    default_chunksize: int = DEFAULT_CHUNK_SIZE
    config: PrimaryDatasetConfig = field(init=False)

    def __post_init__(self) -> None:
        self.config = load_primary_dataset_config(self.config_path)

    @property
    def expected_columns(self) -> tuple[str, ...]:
        return BIFLOW_COLUMNS

    @property
    def required_columns(self) -> tuple[str, ...]:
        return BIFLOW_REQUIRED_COLUMNS

    def available_scenarios(self) -> tuple[str, ...]:
        return tuple(sorted(self.config.scenario_files))

    def scenario_path(self, scenario: str) -> Path:
        return resolve_biflow_csv_path(scenario, self.config)

    def iter_scenario(
        self,
        scenario: str,
        *,
        columns: Sequence[str] | None = None,
        chunksize: int | None = None,
        nrows: int | None = None,
    ) -> Iterator[pd.DataFrame]:
        """Yield cleaned bi-flow chunks for a single scenario."""

        csv_path = self.scenario_path(scenario)
        yield from iter_consistent_csv(
            csv_path,
            expected_columns=self.expected_columns,
            string_columns=BIFLOW_STRING_COLUMNS,
            numeric_columns=BIFLOW_NUMERIC_COLUMNS,
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
            string_columns=BIFLOW_STRING_COLUMNS,
            numeric_columns=BIFLOW_NUMERIC_COLUMNS,
            columns=columns,
            nrows=nrows,
            chunksize=self.default_chunksize,
        )
