"""Shared helpers for frozen-scope dataset loaders."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Sequence

import pandas as pd
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_CONFIG_PATH = REPO_ROOT / "configs" / "data.yaml"
DEFAULT_CHUNK_SIZE = 200_000


class LoaderConfigError(ValueError):
    """Raised when the frozen data config is incomplete or inconsistent."""


class ScenarioNotFoundError(KeyError):
    """Raised when a requested scenario is not defined by the frozen config."""


@dataclass(frozen=True)
class PrimaryDatasetConfig:
    """Resolved primary-dataset paths and scenario mappings."""

    root: Path
    packet_features_dir: Path
    biflow_features_dir: Path
    uniflow_features_dir: Path
    pcap_dir: Path
    scenario_files: Mapping[str, str]
    packet_schema: Mapping[str, str]
    biflow_schema: Mapping[str, str]
    uniflow_schema: Mapping[str, str]
    broker_ip: str
    broker_port: int


def _resolve_repo_path(raw_path: str | Path) -> Path:
    path = Path(raw_path)
    return path if path.is_absolute() else REPO_ROOT / path


def load_primary_dataset_config(
    config_path: str | Path = DEFAULT_DATA_CONFIG_PATH,
) -> PrimaryDatasetConfig:
    """Load the frozen primary-dataset configuration from YAML."""

    resolved_config_path = _resolve_repo_path(config_path)
    with resolved_config_path.open() as handle:
        config = yaml.safe_load(handle)

    primary = config.get("primary_dataset", {})
    sources = primary.get("sources", {})
    files = primary.get("files", {})
    attack_families = files.get("attack_families", {})
    if "normal" not in files:
        raise LoaderConfigError("primary_dataset.files.normal is required")

    scenario_files = {"normal": files["normal"], **attack_families}
    broker_context = config.get("windowing", {}).get("broker_context", {})

    return PrimaryDatasetConfig(
        root=_resolve_repo_path(primary["root"]),
        packet_features_dir=_resolve_repo_path(sources["packet_features_dir"]),
        biflow_features_dir=_resolve_repo_path(sources["biflow_features_dir"]),
        uniflow_features_dir=_resolve_repo_path(sources["uniflow_features_dir"]),
        pcap_dir=_resolve_repo_path(sources["pcap_dir"]),
        scenario_files=scenario_files,
        packet_schema=primary.get("packet_schema", {}),
        biflow_schema=primary.get("biflow_schema", {}),
        uniflow_schema=primary.get("uniflow_schema", {}),
        broker_ip=str(broker_context.get("broker_ip", "")),
        broker_port=int(broker_context.get("broker_port", 1883)),
    )


def resolve_packet_csv_path(
    scenario: str,
    config: PrimaryDatasetConfig,
) -> Path:
    """Resolve the packet-level CSV for a frozen-scope scenario."""

    if scenario not in config.scenario_files:
        available = ", ".join(sorted(config.scenario_files))
        raise ScenarioNotFoundError(
            f"Unknown scenario '{scenario}'. Available scenarios: {available}"
        )
    return config.packet_features_dir / config.scenario_files[scenario]


def resolve_biflow_csv_path(
    scenario: str,
    config: PrimaryDatasetConfig,
) -> Path:
    """Resolve the bi-flow CSV using the dataset's naming convention."""

    packet_path = resolve_packet_csv_path(scenario, config)
    return config.biflow_features_dir / f"biflow_{packet_path.name}"


def validate_requested_columns(
    columns: Sequence[str] | None,
    expected_columns: Sequence[str],
) -> list[str]:
    """Ensure column subsets stay inside the frozen raw schema."""

    expected = set(expected_columns)
    if columns is None:
        return list(expected_columns)

    missing = [column for column in columns if column not in expected]
    if missing:
        missing_text = ", ".join(missing)
        raise LoaderConfigError(f"Requested unknown columns: {missing_text}")
    return list(columns)


def drop_duplicate_header_rows(frame: pd.DataFrame) -> pd.DataFrame:
    """Drop embedded header rows that appear inside several packet CSVs."""

    if frame.empty:
        return frame

    header_mask = pd.Series(True, index=frame.index)
    for column in frame.columns:
        header_mask &= frame[column].astype("string").fillna("") == column
    if not header_mask.any():
        return frame
    return frame.loc[~header_mask].copy()


def coerce_schema(
    frame: pd.DataFrame,
    *,
    string_columns: Sequence[str],
    numeric_columns: Sequence[str],
) -> pd.DataFrame:
    """Apply stable string/numeric dtypes after raw-row cleanup."""

    if frame.empty:
        return frame

    coerced = frame.copy()
    string_set = set(string_columns)
    numeric_set = set(numeric_columns)

    for column in coerced.columns:
        if column in numeric_set:
            coerced[column] = pd.to_numeric(coerced[column], errors="coerce")
        elif column in string_set:
            coerced[column] = coerced[column].astype("string")

    return coerced.convert_dtypes()


def iter_consistent_csv(
    csv_path: str | Path,
    *,
    expected_columns: Sequence[str],
    string_columns: Sequence[str],
    numeric_columns: Sequence[str],
    columns: Sequence[str] | None = None,
    chunksize: int = DEFAULT_CHUNK_SIZE,
    nrows: int | None = None,
) -> Iterator[pd.DataFrame]:
    """Yield cleaned chunks with duplicate headers removed and types coerced."""

    resolved_path = _resolve_repo_path(csv_path)
    selected_columns = validate_requested_columns(columns, expected_columns)
    remaining_rows = nrows
    effective_chunksize = chunksize
    if nrows is not None:
        effective_chunksize = min(chunksize, max(nrows, 1_000))

    reader = pd.read_csv(
        resolved_path,
        usecols=selected_columns,
        dtype="string",
        chunksize=effective_chunksize,
        low_memory=False,
    )
    for raw_chunk in reader:
        cleaned_chunk = drop_duplicate_header_rows(raw_chunk)
        cleaned_chunk = coerce_schema(
            cleaned_chunk,
            string_columns=string_columns,
            numeric_columns=numeric_columns,
        )
        if cleaned_chunk.empty:
            continue

        if remaining_rows is not None:
            if remaining_rows <= 0:
                break
            if len(cleaned_chunk) > remaining_rows:
                yield cleaned_chunk.head(remaining_rows).copy()
                break
            remaining_rows -= len(cleaned_chunk)

        yield cleaned_chunk


def load_consistent_csv(
    csv_path: str | Path,
    *,
    expected_columns: Sequence[str],
    string_columns: Sequence[str],
    numeric_columns: Sequence[str],
    columns: Sequence[str] | None = None,
    nrows: int | None = None,
    chunksize: int = DEFAULT_CHUNK_SIZE,
) -> pd.DataFrame:
    """Load a cleaned DataFrame, concatenating cleaned chunks as needed."""

    chunks = list(
        iter_consistent_csv(
            csv_path,
            expected_columns=expected_columns,
            string_columns=string_columns,
            numeric_columns=numeric_columns,
            columns=columns,
            chunksize=chunksize,
            nrows=nrows,
        )
    )
    selected_columns = validate_requested_columns(columns, expected_columns)
    if not chunks:
        return pd.DataFrame(columns=selected_columns)
    return pd.concat(chunks, ignore_index=True)
