"""Shared helpers for frozen-scope windowing and Phase 2 outputs."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Iterable

import pandas as pd
import yaml

from src.loaders.common import REPO_ROOT


TIMESTAMP_FORMAT = "%m/%d/%Y, %H:%M:%S:%f"


def load_yaml_config(path: str | Path) -> dict[str, Any]:
    """Load a YAML config relative to the repository root when needed."""

    resolved = Path(path)
    if not resolved.is_absolute():
        resolved = REPO_ROOT / resolved
    with resolved.open() as handle:
        return yaml.safe_load(handle)


def ensure_directory(path: str | Path) -> Path:
    """Create a directory when it does not already exist."""

    resolved = Path(path)
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def ensure_parent(path: str | Path) -> Path:
    """Create the parent directory for a file path."""

    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def parse_packet_timestamps(series: pd.Series) -> pd.Series:
    """Parse frozen packet timestamps using the dataset's explicit format."""

    return pd.to_datetime(series, format=TIMESTAMP_FORMAT, errors="coerce")


def safe_divide(numerator: float, denominator: float) -> float:
    """Return a stable ratio without emitting inf or NaN."""

    if denominator in (0, 0.0) or pd.isna(denominator):
        return 0.0
    if pd.isna(numerator):
        return 0.0
    return float(numerator) / float(denominator)


def population_std_from_sums(
    count: int,
    value_sum: float,
    value_sumsq: float,
) -> float:
    """Compute a population standard deviation from stable aggregate sums."""

    if count <= 0:
        return 0.0
    mean = float(value_sum) / float(count)
    variance = max((float(value_sumsq) / float(count)) - (mean * mean), 0.0)
    return math.sqrt(variance)


def entropy_from_counts(counts: Iterable[int]) -> float:
    """Compute Shannon entropy over a finite set of non-negative counts."""

    count_list = [int(value) for value in counts if int(value) > 0]
    total = sum(count_list)
    if total <= 0:
        return 0.0

    entropy = 0.0
    for count in count_list:
        probability = float(count) / float(total)
        entropy -= probability * math.log2(probability)
    return entropy


def window_id_from_parts(
    broker_ip: str,
    peer_ip: str,
    peer_port: int | float | str,
    window_start: pd.Timestamp,
) -> str:
    """Build a stable string identifier for one broker-facing window."""

    if pd.isna(peer_port):
        port_text = "NA"
    else:
        port_text = str(int(peer_port))
    return f"{broker_ip}|{peer_ip}|{port_text}|{window_start.isoformat()}"


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    """Write JSON with stable formatting."""

    resolved = ensure_parent(path)
    resolved.write_text(json.dumps(payload, indent=2, sort_keys=True))


def write_text(path: str | Path, text: str) -> None:
    """Write UTF-8 text, ensuring the parent directory exists first."""

    resolved = ensure_parent(path)
    resolved.write_text(text, encoding="utf-8")


def append_feature_coverage_rows(
    coverage_path: str | Path,
    rows: list[dict[str, Any]],
) -> None:
    """Append or replace feature coverage rows keyed by feature/source."""

    resolved = ensure_parent(coverage_path)
    new_frame = pd.DataFrame(rows)
    if resolved.exists():
        existing = pd.read_csv(resolved)
        combined = pd.concat([existing, new_frame], ignore_index=True)
        dedupe_key = ["feature_name", "source_dataset", "source_granularity"]
        combined = combined.drop_duplicates(subset=dedupe_key, keep="last")
    else:
        combined = new_frame

    combined = combined.sort_values(
        by=["source_dataset", "source_granularity", "feature_name"],
        kind="stable",
    )
    combined.to_csv(resolved, index=False)
