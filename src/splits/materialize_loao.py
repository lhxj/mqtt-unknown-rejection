"""Materialize frozen-scope LOAO fold manifests after packet windowing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd

from src.windowing.common import ensure_directory, load_yaml_config, write_json, write_text


REPO_ROOT = Path(__file__).resolve().parents[2]
WINDOW_DIR = REPO_ROOT / "data" / "interim" / "windows" / "packet"
OUTPUT_DIR = REPO_ROOT / "data" / "processed" / "splits"
COUNT_TABLE_PATH = REPO_ROOT / "outputs" / "tables" / "tab_loao_split_counts.csv"
LOG_PATH = REPO_ROOT / "outputs" / "logs" / "split_materialization.log"


def _window_path(scenario: str) -> Path:
    """Resolve the main window parquet for one scenario."""

    if scenario == "normal":
        return WINDOW_DIR / "normal_windows.parquet"
    return WINDOW_DIR / f"{scenario}_attack_windows.parquet"


def _load_main_windows() -> dict[str, pd.DataFrame]:
    """Load the packet-window tables needed for LOAO split materialization."""

    tables: dict[str, pd.DataFrame] = {}
    for scenario in ["normal", "scan_A", "scan_sU", "sparta", "mqtt_bruteforce"]:
        path = _window_path(scenario)
        if not path.exists():
            raise FileNotFoundError(
                f"Required window file is missing: {path}. "
                "Run src/windowing/build_packet_windows.py first."
            )
        frame = pd.read_parquet(path)
        frame["peer_port"] = pd.to_numeric(frame["peer_port"], errors="coerce").astype(int)
        tables[scenario] = frame
    return tables


def _shuffle_groups(frame: pd.DataFrame, group_columns: list[str], seed: int) -> pd.DataFrame:
    """Return a deterministic shuffled unique-group table."""

    groups = frame[group_columns].drop_duplicates().reset_index(drop=True)
    if groups.empty:
        return groups
    return groups.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def _assign_three_way(
    frame: pd.DataFrame,
    *,
    group_columns: list[str],
    train_fraction: float,
    validation_fraction: float,
    seed: int,
) -> pd.DataFrame:
    """Assign groups into train/validation/test partitions."""

    shuffled = _shuffle_groups(frame, group_columns, seed)
    group_count = len(shuffled)
    if group_count == 0:
        assigned = frame.copy()
        assigned["partition"] = pd.Series(dtype="string")
        return assigned

    train_cut = int(group_count * train_fraction)
    validation_cut = train_cut + int(group_count * validation_fraction)
    if group_count >= 3:
        train_cut = max(train_cut, 1)
        validation_cut = max(validation_cut, train_cut + 1)
        validation_cut = min(validation_cut, group_count - 1)

    shuffled = shuffled.copy()
    shuffled["partition"] = "test"
    shuffled.loc[: train_cut - 1, "partition"] = "train"
    shuffled.loc[train_cut: validation_cut - 1, "partition"] = "validation"
    assigned = frame.merge(shuffled, on=group_columns, how="left", validate="m:1")
    return assigned


def _assign_two_way(
    frame: pd.DataFrame,
    *,
    group_columns: list[str],
    validation_fraction: float,
    seed: int,
) -> pd.DataFrame:
    """Assign groups into train/validation partitions."""

    shuffled = _shuffle_groups(frame, group_columns, seed)
    group_count = len(shuffled)
    if group_count == 0:
        assigned = frame.copy()
        assigned["partition"] = pd.Series(dtype="string")
        return assigned

    validation_count = int(group_count * validation_fraction)
    if group_count >= 2:
        validation_count = max(validation_count, 1)
        validation_count = min(validation_count, group_count - 1)

    shuffled = shuffled.copy()
    shuffled["partition"] = "train"
    if validation_count > 0:
        shuffled.loc[: validation_count - 1, "partition"] = "validation"
    assigned = frame.merge(shuffled, on=group_columns, how="left", validate="m:1")
    return assigned


def _window_ids_by_scenario(frame: pd.DataFrame) -> dict[str, list[str]]:
    """Group window ids by source scenario for manifest serialization."""

    grouped: dict[str, list[str]] = {}
    if frame.empty:
        return grouped
    for scenario, scenario_frame in frame.groupby("scenario", sort=False):
        grouped[str(scenario)] = scenario_frame["window_id"].astype(str).tolist()
    return grouped


def _concat_non_empty(frames: list[pd.DataFrame], columns: list[str]) -> pd.DataFrame:
    """Concatenate frames while tolerating legitimately empty scenario tables."""

    non_empty = [frame for frame in frames if not frame.empty]
    if not non_empty:
        return pd.DataFrame(columns=columns)
    return pd.concat(non_empty, ignore_index=True)


def _group_overlap_count(
    left: pd.DataFrame,
    right: pd.DataFrame,
    group_columns: list[str],
) -> int:
    """Count overlapping groups across two partitions."""

    if left.empty or right.empty:
        return 0
    left_keys = set(map(tuple, left[group_columns].drop_duplicates().to_records(index=False)))
    right_keys = set(map(tuple, right[group_columns].drop_duplicates().to_records(index=False)))
    return len(left_keys & right_keys)


def materialize_loao_splits() -> dict[str, dict[str, Any]]:
    """Materialize the four required LOAO fold manifests."""

    ensure_directory(OUTPUT_DIR)
    ensure_directory(REPO_ROOT / "outputs" / "logs")
    ensure_directory(REPO_ROOT / "outputs" / "tables")

    config = load_yaml_config(REPO_ROOT / "configs" / "split.yaml")
    seed = int(config["random_seed"])
    normal_partition_config = config["normal_source"]["partition"]
    attack_validation_fraction = float(config["train_validation_split"]["validation_fraction"])

    windows = _load_main_windows()
    normal_frame = windows["normal"]
    normal_group_columns = list(normal_partition_config["group_by"])
    attack_group_columns = list(config["train_validation_split"]["group_by"])

    normal_assigned = _assign_three_way(
        normal_frame,
        group_columns=normal_group_columns,
        train_fraction=float(normal_partition_config["train_fraction"]),
        validation_fraction=float(normal_partition_config["validation_fraction"]),
        seed=seed,
    )

    manifests: dict[str, dict[str, Any]] = {}
    count_rows: list[dict[str, Any]] = []
    log_lines = ["LOAO split materialization summary", ""]

    for fold_index, fold in enumerate(config["folds"]):
        fold_name = str(fold["name"])
        heldout_family = str(fold["holdout_family"])
        seen_families = list(fold["seen_families"])

        seen_frame = _concat_non_empty(
            [windows[family] for family in seen_families],
            columns=list(normal_frame.columns),
        )
        seen_assigned = _assign_two_way(
            seen_frame,
            group_columns=attack_group_columns,
            validation_fraction=attack_validation_fraction,
            seed=seed + ((fold_index + 1) * 101),
        )

        train_frame = _concat_non_empty(
            [
                normal_assigned.loc[normal_assigned["partition"] == "train"].copy(),
                seen_assigned.loc[seen_assigned["partition"] == "train"].copy(),
            ],
            columns=list(normal_frame.columns) + ["partition"],
        )
        validation_frame = _concat_non_empty(
            [
                normal_assigned.loc[normal_assigned["partition"] == "validation"].copy(),
                seen_assigned.loc[seen_assigned["partition"] == "validation"].copy(),
            ],
            columns=list(normal_frame.columns) + ["partition"],
        )
        test_normal_frame = normal_assigned.loc[normal_assigned["partition"] == "test"].copy()
        test_heldout_frame = windows[heldout_family].copy()
        test_frame = _concat_non_empty(
            [test_normal_frame, test_heldout_frame],
            columns=list(normal_frame.columns) + ["partition"],
        )

        normal_train = normal_assigned.loc[normal_assigned["partition"] == "train"].copy()
        normal_validation = normal_assigned.loc[normal_assigned["partition"] == "validation"].copy()
        normal_test = normal_assigned.loc[normal_assigned["partition"] == "test"].copy()

        normal_overlap = (
            _group_overlap_count(normal_train, normal_validation, normal_group_columns)
            + _group_overlap_count(normal_train, normal_test, normal_group_columns)
            + _group_overlap_count(normal_validation, normal_test, normal_group_columns)
        )
        seen_overlap = _group_overlap_count(
            seen_assigned.loc[seen_assigned["partition"] == "train"],
            seen_assigned.loc[seen_assigned["partition"] == "validation"],
            attack_group_columns,
        )

        seen_family_counts = {
            family: int(len(seen_frame.loc[seen_frame["family"] == family]))
            for family in seen_families
        }

        manifest = {
            "fold_name": fold_name,
            "heldout_family": heldout_family,
            "seen_families": seen_families,
            "window_stage": config["split_stage"],
            "window_key": ["broker_ip", "peer_ip", "peer_port", "window_start_5s"],
            "files": {scenario: str(_window_path(scenario)) for scenario in windows},
            "counts": {
                "train_window_count": int(len(train_frame)),
                "validation_window_count": int(len(validation_frame)),
                "test_normal_window_count": int(len(test_normal_frame)),
                "test_heldout_attack_window_count": int(len(test_heldout_frame)),
            },
            "partitions": {
                "train": {
                    "window_ids_by_scenario": _window_ids_by_scenario(train_frame),
                },
                "validation": {
                    "window_ids_by_scenario": _window_ids_by_scenario(validation_frame),
                },
                "test_normal": {
                    "window_ids_by_scenario": _window_ids_by_scenario(test_normal_frame),
                },
                "test_heldout_attack": {
                    "window_ids_by_scenario": _window_ids_by_scenario(test_heldout_frame),
                },
                "test_all": {
                    "window_ids_by_scenario": _window_ids_by_scenario(test_frame),
                },
            },
            "checks": {
                "normal_group_overlap_count": int(normal_overlap),
                "seen_group_overlap_count": int(seen_overlap),
                "heldout_family_unseen_before_test": True,
            },
        }
        manifests[fold_name] = manifest
        write_json(OUTPUT_DIR / f"{fold_name}.json", manifest)

        count_rows.append(
            {
                "fold_name": fold_name,
                "train_window_count": int(len(train_frame)),
                "validation_window_count": int(len(validation_frame)),
                "test_normal_window_count": int(len(test_normal_frame)),
                "test_heldout_attack_window_count": int(len(test_heldout_frame)),
                "seen_family_counts": json.dumps(seen_family_counts, sort_keys=True),
                "heldout_family_name": heldout_family,
            }
        )

        log_lines.extend(
            [
                f"[{fold_name}]",
                f"heldout_family={heldout_family}",
                f"seen_families={', '.join(seen_families)}",
                f"train_window_count={len(train_frame)}",
                f"validation_window_count={len(validation_frame)}",
                f"test_normal_window_count={len(test_normal_frame)}",
                f"test_heldout_attack_window_count={len(test_heldout_frame)}",
                f"normal_group_overlap_count={normal_overlap}",
                f"seen_group_overlap_count={seen_overlap}",
                "",
            ]
        )

    pd.DataFrame(count_rows).to_csv(COUNT_TABLE_PATH, index=False)
    write_text(LOG_PATH, "\n".join(log_lines) + "\n")
    return manifests


def main() -> None:
    """CLI entry point for LOAO split materialization."""

    materialize_loao_splits()


if __name__ == "__main__":
    main()
