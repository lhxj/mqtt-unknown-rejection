"""Materialize Phase 2.5 benchmark-cleanup split artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd

from src.loaders.biflow_loader import BiflowLoader
from src.windowing.common import ensure_directory, load_yaml_config, write_json, write_text


REPO_ROOT = Path(__file__).resolve().parents[2]
SPLIT_CONFIG_PATH = REPO_ROOT / "configs" / "split.yaml"
DATA_CONFIG_PATH = REPO_ROOT / "configs" / "data.yaml"

MAIN_MANIFEST_DIR = REPO_ROOT / "data" / "processed" / "splits" / "main_loao_biflow"
PACKET_MANIFEST_DIR = REPO_ROOT / "data" / "processed" / "splits" / "focused_packet_semantic"

BENCHMARK_LOG_PATH = REPO_ROOT / "outputs" / "logs" / "benchmark_cleanup.log"
MAIN_COUNT_TABLE_PATH = REPO_ROOT / "outputs" / "tables" / "tab_biflow_loao_split_counts.csv"
PACKET_COUNT_TABLE_PATH = REPO_ROOT / "outputs" / "tables" / "tab_packet_semantic_split_counts.csv"
DEFINITION_TABLE_PATH = REPO_ROOT / "outputs" / "tables" / "tab_main_benchmark_definition.csv"
REPORT_PATH = REPO_ROOT / "reports" / "benchmark_viability_cleanup.md"


def _shuffle_groups(frame: pd.DataFrame, group_column: str, seed: int) -> pd.DataFrame:
    """Return shuffled unique groups for deterministic partitioning."""

    groups = frame[[group_column]].drop_duplicates().reset_index(drop=True)
    if groups.empty:
        return groups
    return groups.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def _assign_three_way(
    frame: pd.DataFrame,
    *,
    group_column: str,
    train_fraction: float,
    validation_fraction: float,
    seed: int,
) -> pd.DataFrame:
    """Assign groups into train/validation/test partitions."""

    shuffled = _shuffle_groups(frame, group_column, seed)
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
    return frame.merge(shuffled, on=group_column, how="left", validate="m:1")


def _assign_two_way(
    frame: pd.DataFrame,
    *,
    group_column: str,
    validation_fraction: float,
    seed: int,
) -> pd.DataFrame:
    """Assign groups into train/validation partitions."""

    shuffled = _shuffle_groups(frame, group_column, seed)
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
    return frame.merge(shuffled, on=group_column, how="left", validate="m:1")


def _group_overlap_count(left: pd.DataFrame, right: pd.DataFrame, group_column: str) -> int:
    """Count overlapping groups between two partitions."""

    if left.empty or right.empty:
        return 0
    left_groups = set(left[group_column].drop_duplicates().tolist())
    right_groups = set(right[group_column].drop_duplicates().tolist())
    return len(left_groups & right_groups)


def _biflow_group_id(row: pd.Series) -> str:
    """Create an order-invariant endpoint group id for biflow splitting."""

    endpoint_a = f"{row['ip_src']}:{int(row['prt_src'])}"
    endpoint_b = f"{row['ip_dst']}:{int(row['prt_dst'])}"
    endpoint_low, endpoint_high = sorted([endpoint_a, endpoint_b])
    return f"{endpoint_low}|{endpoint_high}|proto={int(row['proto'])}"


def _load_biflow_split_metadata(
    *,
    scenario: str,
    processed_path: Path,
    loader: BiflowLoader,
) -> pd.DataFrame:
    """Recover processed-row split metadata from aligned raw biflow CSVs."""

    columns = ["ip_src", "ip_dst", "prt_src", "prt_dst", "proto", "is_attack"]
    kept_chunks: list[pd.DataFrame] = []
    sample_index = 0

    for chunk in loader.iter_scenario(scenario, columns=columns, chunksize=200_000):
        working = chunk.copy()
        working["is_attack"] = pd.to_numeric(working["is_attack"], errors="coerce").fillna(0).astype(int)
        working["prt_src"] = pd.to_numeric(working["prt_src"], errors="coerce")
        working["prt_dst"] = pd.to_numeric(working["prt_dst"], errors="coerce")
        working["proto"] = pd.to_numeric(working["proto"], errors="coerce")
        working = working.dropna(subset=["prt_src", "prt_dst", "proto"]).copy()
        working["prt_src"] = working["prt_src"].astype(int)
        working["prt_dst"] = working["prt_dst"].astype(int)
        working["proto"] = working["proto"].astype(int)

        if scenario == "normal":
            kept = working.loc[working["is_attack"] == 0].copy()
        else:
            kept = working.loc[working["is_attack"] == 1].copy()
        if kept.empty:
            continue

        kept["sample_index"] = range(sample_index, sample_index + len(kept))
        sample_index += len(kept)
        kept["group_id"] = kept.apply(_biflow_group_id, axis=1)
        kept["scenario"] = scenario
        kept["family"] = "normal" if scenario == "normal" else scenario
        kept_chunks.append(kept[["sample_index", "group_id", "scenario", "family"]].copy())

    metadata = pd.concat(kept_chunks, ignore_index=True) if kept_chunks else pd.DataFrame(
        columns=["sample_index", "group_id", "scenario", "family"]
    )
    processed = pd.read_parquet(processed_path)
    if len(metadata) != len(processed):
        raise ValueError(
            f"Biflow metadata alignment failed for {scenario}: "
            f"raw-retained rows={len(metadata)} processed rows={len(processed)}"
        )
    return metadata


def _packet_group_id(frame: pd.DataFrame) -> pd.Series:
    """Create group ids for packet-window split partitioning."""

    return frame["peer_ip"].astype(str) + "|" + frame["peer_port"].astype(str)


def _main_row_indices_by_scenario(frame: pd.DataFrame) -> dict[str, list[int]]:
    """Serialize sample indices grouped by source scenario."""

    grouped: dict[str, list[int]] = {}
    if frame.empty:
        return grouped
    for scenario, scenario_frame in frame.groupby("scenario", sort=False):
        grouped[str(scenario)] = scenario_frame["sample_index"].astype(int).tolist()
    return grouped


def _window_ids_by_scenario(frame: pd.DataFrame) -> dict[str, list[str]]:
    """Serialize packet window ids grouped by source scenario."""

    grouped: dict[str, list[str]] = {}
    if frame.empty:
        return grouped
    for scenario, scenario_frame in frame.groupby("scenario", sort=False):
        grouped[str(scenario)] = scenario_frame["window_id"].astype(str).tolist()
    return grouped


def _concat_non_empty(frames: list[pd.DataFrame], columns: list[str]) -> pd.DataFrame:
    """Concatenate only non-empty frames."""

    non_empty = [frame for frame in frames if not frame.empty]
    if not non_empty:
        return pd.DataFrame(columns=columns)
    return pd.concat(non_empty, ignore_index=True)


def _materialize_main_biflow_track(
    split_config: dict[str, Any],
    data_config: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """Build main biflow LOAO manifests, counts, and log lines."""

    ensure_directory(MAIN_MANIFEST_DIR)
    loader = BiflowLoader()
    main_config = split_config["main_loao_biflow"]
    source_config = main_config["source"]
    files = source_config["files"]
    processed_dir = REPO_ROOT / source_config["processed_dir"]
    seed = int(split_config["random_seed"])

    scenario_files = {
        "normal": files["normal"],
        **files["attack_families"],
    }
    metadata_by_scenario = {
        scenario: _load_biflow_split_metadata(
            scenario=scenario,
            processed_path=processed_dir / filename,
            loader=loader,
        )
        for scenario, filename in scenario_files.items()
    }

    normal_partition = main_config["normal_source"]["partition"]
    normal_assigned = _assign_three_way(
        metadata_by_scenario["normal"],
        group_column="group_id",
        train_fraction=float(normal_partition["train_fraction"]),
        validation_fraction=float(normal_partition["validation_fraction"]),
        seed=seed,
    )

    count_rows: list[dict[str, Any]] = []
    log_lines = ["[main_loao_biflow]", "source=data/processed/biflow", ""]
    definition_rows: list[dict[str, Any]] = [
        {
            "track_name": "main_loao_biflow",
            "dataset": data_config["primary_dataset"]["name"],
            "granularity": "biflow_features",
            "scope": "family_complete_4_fold_loao_unknown_rejection",
            "families_covered": "normal|scan_A|scan_sU|sparta|mqtt_bruteforce",
            "intended_use": "main benchmark table",
            "scientifically_valid_for_main_table": "yes",
            "notes": "Family-complete after Phase 2.5 cleanup; manifests reference processed biflow matrices.",
        }
    ]

    for fold_index, fold in enumerate(main_config["folds"]):
        fold_name = str(fold["name"])
        heldout_family = str(fold["holdout_family"])
        seen_families = list(fold["seen_families"])

        seen_train_parts: list[pd.DataFrame] = []
        seen_validation_parts: list[pd.DataFrame] = []
        seen_group_overlap = 0
        seen_attack_total_train = 0
        seen_attack_total_validation = 0

        for family_offset, family in enumerate(seen_families):
            family_assigned = _assign_two_way(
                metadata_by_scenario[family],
                group_column="group_id",
                validation_fraction=float(main_config["seen_family_partition"]["validation_fraction"]),
                seed=seed + ((fold_index + 1) * 101) + family_offset,
            )
            family_train = family_assigned.loc[family_assigned["partition"] == "train"].copy()
            family_validation = family_assigned.loc[
                family_assigned["partition"] == "validation"
            ].copy()
            seen_group_overlap += _group_overlap_count(
                family_train,
                family_validation,
                "group_id",
            )
            seen_attack_total_train += len(family_train)
            seen_attack_total_validation += len(family_validation)
            seen_train_parts.append(family_train)
            seen_validation_parts.append(family_validation)

        train_frame = _concat_non_empty(
            [
                normal_assigned.loc[normal_assigned["partition"] == "train"].copy(),
                *seen_train_parts,
            ],
            columns=["sample_index", "group_id", "scenario", "family", "partition"],
        )
        validation_frame = _concat_non_empty(
            [
                normal_assigned.loc[normal_assigned["partition"] == "validation"].copy(),
                *seen_validation_parts,
            ],
            columns=["sample_index", "group_id", "scenario", "family", "partition"],
        )
        test_normal_frame = normal_assigned.loc[normal_assigned["partition"] == "test"].copy()
        test_heldout_frame = metadata_by_scenario[heldout_family].copy()
        test_frame = _concat_non_empty(
            [test_normal_frame, test_heldout_frame],
            columns=["sample_index", "group_id", "scenario", "family", "partition"],
        )

        normal_train = normal_assigned.loc[normal_assigned["partition"] == "train"].copy()
        normal_validation = normal_assigned.loc[normal_assigned["partition"] == "validation"].copy()
        normal_test = normal_assigned.loc[normal_assigned["partition"] == "test"].copy()

        normal_overlap = (
            _group_overlap_count(normal_train, normal_validation, "group_id")
            + _group_overlap_count(normal_train, normal_test, "group_id")
            + _group_overlap_count(normal_validation, normal_test, "group_id")
        )

        manifest = {
            "track_name": "main_loao_biflow",
            "fold_name": fold_name,
            "heldout_family": heldout_family,
            "seen_families": seen_families,
            "source": {
                "dataset": data_config["primary_dataset"]["name"],
                "granularity": "biflow_features",
                "processed_dir": str(processed_dir),
                "processed_files": scenario_files,
                "sample_id_type": "processed_row_index",
            },
            "partitions": {
                "train": {"row_indices_by_scenario": _main_row_indices_by_scenario(train_frame)},
                "validation": {
                    "row_indices_by_scenario": _main_row_indices_by_scenario(validation_frame)
                },
                "test_normal": {
                    "row_indices_by_scenario": _main_row_indices_by_scenario(test_normal_frame)
                },
                "test_heldout_attack": {
                    "row_indices_by_scenario": _main_row_indices_by_scenario(test_heldout_frame)
                },
                "test_all": {"row_indices_by_scenario": _main_row_indices_by_scenario(test_frame)},
            },
            "counts": {
                "train_normal_count": int(len(normal_train)),
                "train_seen_attack_count": int(seen_attack_total_train),
                "validation_normal_count": int(len(normal_validation)),
                "validation_seen_attack_count": int(seen_attack_total_validation),
                "test_normal_count": int(len(test_normal_frame)),
                "test_heldout_attack_count": int(len(test_heldout_frame)),
            },
            "checks": {
                "normal_group_overlap_count": int(normal_overlap),
                "seen_group_overlap_count": int(seen_group_overlap),
                "heldout_family_unseen_before_test": True,
            },
            "notes": [
                "This is the family-complete main benchmark after Phase 2.5 cleanup.",
                "Split grouping used raw biflow endpoint metadata aligned back to processed row indices.",
            ],
        }
        write_json(MAIN_MANIFEST_DIR / f"{fold_name}.json", manifest)

        count_rows.append(
            {
                "fold_name": fold_name,
                "train_normal_count": int(len(normal_train)),
                "train_seen_attack_count": int(seen_attack_total_train),
                "validation_normal_count": int(len(normal_validation)),
                "validation_seen_attack_count": int(seen_attack_total_validation),
                "test_normal_count": int(len(test_normal_frame)),
                "test_heldout_attack_count": int(len(test_heldout_frame)),
                "heldout_family": heldout_family,
            }
        )
        log_lines.extend(
            [
                f"{fold_name}: train_normal={len(normal_train)}, train_seen_attack={seen_attack_total_train}, "
                f"validation_normal={len(normal_validation)}, validation_seen_attack={seen_attack_total_validation}, "
                f"test_normal={len(test_normal_frame)}, test_heldout_attack={len(test_heldout_frame)}, "
                f"normal_group_overlap={normal_overlap}, seen_group_overlap={seen_group_overlap}",
            ]
        )

    return count_rows, log_lines, definition_rows


def _materialize_packet_semantic_track(
    split_config: dict[str, Any],
    data_config: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """Build the focused packet semantic manifest, counts, and log lines."""

    ensure_directory(PACKET_MANIFEST_DIR)
    packet_config = split_config["focused_packet_semantic"]
    source_config = packet_config["source"]
    processed_dir = REPO_ROOT / source_config["processed_dir"]
    seed = int(split_config["random_seed"])

    normal_path = processed_dir / source_config["files"]["normal"]
    mqtt_path = processed_dir / source_config["files"]["mqtt_bruteforce"]

    normal_frame = pd.read_parquet(normal_path).copy()
    mqtt_frame = pd.read_parquet(mqtt_path).copy()
    for frame, scenario in [(normal_frame, "normal"), (mqtt_frame, "mqtt_bruteforce")]:
        frame["scenario"] = scenario
        frame["group_id"] = _packet_group_id(frame)

    partition_config = packet_config["partition"]
    normal_assigned = _assign_three_way(
        normal_frame,
        group_column="group_id",
        train_fraction=float(partition_config["train_fraction"]),
        validation_fraction=float(partition_config["validation_fraction"]),
        seed=seed,
    )
    mqtt_assigned = _assign_three_way(
        mqtt_frame,
        group_column="group_id",
        train_fraction=float(partition_config["train_fraction"]),
        validation_fraction=float(partition_config["validation_fraction"]),
        seed=seed + 701,
    )

    train_normal = normal_assigned.loc[normal_assigned["partition"] == "train"].copy()
    validation_normal = normal_assigned.loc[normal_assigned["partition"] == "validation"].copy()
    test_normal = normal_assigned.loc[normal_assigned["partition"] == "test"].copy()

    train_mqtt = mqtt_assigned.loc[mqtt_assigned["partition"] == "train"].copy()
    validation_mqtt = mqtt_assigned.loc[mqtt_assigned["partition"] == "validation"].copy()
    test_mqtt = mqtt_assigned.loc[mqtt_assigned["partition"] == "test"].copy()

    train_frame = _concat_non_empty(
        [train_normal, train_mqtt],
        columns=list(normal_frame.columns) + ["group_id", "partition"],
    )
    validation_frame = _concat_non_empty(
        [validation_normal, validation_mqtt],
        columns=list(normal_frame.columns) + ["group_id", "partition"],
    )
    test_frame = _concat_non_empty(
        [test_normal, test_mqtt],
        columns=list(normal_frame.columns) + ["group_id", "partition"],
    )

    normal_overlap = (
        _group_overlap_count(train_normal, validation_normal, "group_id")
        + _group_overlap_count(train_normal, test_normal, "group_id")
        + _group_overlap_count(validation_normal, test_normal, "group_id")
    )
    mqtt_overlap = (
        _group_overlap_count(train_mqtt, validation_mqtt, "group_id")
        + _group_overlap_count(train_mqtt, test_mqtt, "group_id")
        + _group_overlap_count(validation_mqtt, test_mqtt, "group_id")
    )

    manifest = {
        "track_name": "focused_packet_semantic",
        "split_name": "normal_mqtt_bruteforce_split",
        "source": {
            "dataset": data_config["primary_dataset"]["name"],
            "granularity": "packet_windows",
            "processed_dir": str(processed_dir),
            "files": source_config["files"],
            "sample_id_type": "window_id",
        },
        "families": ["normal", "mqtt_bruteforce"],
        "partitions": {
            "train": {"window_ids_by_scenario": _window_ids_by_scenario(train_frame)},
            "validation": {"window_ids_by_scenario": _window_ids_by_scenario(validation_frame)},
            "test": {"window_ids_by_scenario": _window_ids_by_scenario(test_frame)},
        },
        "counts": {
            "train_normal_count": int(len(train_normal)),
            "train_mqtt_bruteforce_count": int(len(train_mqtt)),
            "validation_normal_count": int(len(validation_normal)),
            "validation_mqtt_bruteforce_count": int(len(validation_mqtt)),
            "test_normal_count": int(len(test_normal)),
            "test_mqtt_bruteforce_count": int(len(test_mqtt)),
        },
        "checks": {
            "normal_group_overlap_count": int(normal_overlap),
            "mqtt_bruteforce_group_overlap_count": int(mqtt_overlap),
            "family_complete_loao": False,
        },
        "notes": [
            "Focused MQTT-native packet benchmark only.",
            "Not valid for family-complete LOAO claims.",
            "Semantic-lite features remain on the gate path for this track.",
        ],
    }
    write_json(PACKET_MANIFEST_DIR / "normal_mqtt_bruteforce_split.json", manifest)

    count_rows = [
        {
            "split_name": "normal_mqtt_bruteforce_split",
            "train_normal_count": int(len(train_normal)),
            "train_mqtt_bruteforce_count": int(len(train_mqtt)),
            "validation_normal_count": int(len(validation_normal)),
            "validation_mqtt_bruteforce_count": int(len(validation_mqtt)),
            "test_normal_count": int(len(test_normal)),
            "test_mqtt_bruteforce_count": int(len(test_mqtt)),
            "notes": (
                "Focused MQTT-native packet benchmark only; excluded scan_A, scan_sU, and sparta "
                "because broker-facing main attack windows were absent under the frozen definition."
            ),
        }
    ]

    log_lines = [
        "",
        "[focused_packet_semantic]",
        (
            "normal_mqtt_bruteforce_split: "
            f"train_normal={len(train_normal)}, train_mqtt_bruteforce={len(train_mqtt)}, "
            f"validation_normal={len(validation_normal)}, validation_mqtt_bruteforce={len(validation_mqtt)}, "
            f"test_normal={len(test_normal)}, test_mqtt_bruteforce={len(test_mqtt)}, "
            f"normal_group_overlap={normal_overlap}, mqtt_group_overlap={mqtt_overlap}"
        ),
    ]

    definition_rows = [
        {
            "track_name": "focused_packet_semantic",
            "dataset": data_config["primary_dataset"]["name"],
            "granularity": "broker_facing_packet_windows",
            "scope": "focused_mqtt_native_semantic_benchmark",
            "families_covered": "normal|mqtt_bruteforce",
            "intended_use": "focused semantic-lite contribution analysis",
            "scientifically_valid_for_main_table": "no",
            "notes": "scan_A, scan_sU, and sparta had 0 main broker-facing packet attack windows under the frozen definition.",
        },
        {
            "track_name": "mqtt_uad_auxiliary_semantic",
            "dataset": data_config["secondary_dataset"]["name"],
            "granularity": "packet_csv_auxiliary",
            "scope": "semantic_extractability_and_dos_sanity_only",
            "families_covered": "DoS auxiliary only",
            "intended_use": "auxiliary semantic sanity support",
            "scientifically_valid_for_main_table": "no",
            "notes": "MQTT_UAD remains auxiliary only and is not promoted to the main benchmark.",
        },
    ]

    return count_rows, log_lines, definition_rows


def _write_benchmark_cleanup_report(
    *,
    biflow_counts: pd.DataFrame,
    packet_counts: pd.DataFrame,
) -> None:
    """Write the benchmark viability cleanup markdown report."""

    lines = [
        "# Benchmark Viability Cleanup",
        "",
        "## 1. Why the Original Packet LOAO Benchmark Is Degenerate",
        "",
        "- The frozen broker-facing 5-second packet-window definition produced valid main packet windows for `normal` and valid main attack windows for `mqtt_bruteforce`.",
        "- Under that same frozen definition, `scan_A`, `scan_sU`, and `sparta` produced `0` main broker-facing packet attack windows.",
        "- Because three of the four attack families vanish from the main packet table, the original packet LOAO setup cannot support a scientifically valid family-complete 4-fold unknown-rejection benchmark.",
        "- The old packet LOAO manifests remain in the repository only as historical Phase 2 artifacts and must not be treated as current benchmark definitions.",
        "",
        "## 2. Why Biflow Is Now the Family-Complete Main Benchmark",
        "",
        "- The processed biflow matrices cover all five MQTT-IoT-IDS2020 scenarios, including all four attack families.",
        "- The new `main_loao_biflow` track keeps the intended 4-fold LOAO unknown-rejection structure intact: `scan_A`, `scan_sU`, `sparta`, and `mqtt_bruteforce` can each be held out in turn.",
        "- Split manifests reference the processed biflow parquet files while using aligned raw biflow endpoint metadata to keep endpoint groups separated across train, validation, and test partitions.",
        "",
        "Current biflow LOAO count table:",
        "",
        "```text",
        biflow_counts.to_string(index=False),
        "```",
        "",
        "## 3. Why Packet Semantic Evaluation Is Restricted to MQTT-Native Attack Evidence",
        "",
        "- Packet-level semantic-lite features depend on broker-facing MQTT control hints such as message types and coarse connect/connack patterns.",
        "- Those hints survive in the main packet tables for `mqtt_bruteforce`, but not for `scan_A`, `scan_sU`, or `sparta` under the frozen broker-facing definition.",
        "- The `focused_packet_semantic` track is therefore restricted to `normal + mqtt_bruteforce` and is used only to test whether weak behavior-consistency hints help where MQTT-native packet evidence actually exists.",
        "- MQTT_UAD remains auxiliary only for semantic extractability and DoS sanity support; it does not replace MQTT-IoT-IDS2020 as the primary dataset.",
        "",
        "Current focused packet split count table:",
        "",
        "```text",
        packet_counts.to_string(index=False),
        "```",
        "",
        "## 4. What Claims the Paper May Safely Make After This Cleanup",
        "",
        "- The family-complete main benchmark for unknown rejection is MQTT-IoT-IDS2020 biflow LOAO.",
        "- Weak MQTT behavior-consistency features can be evaluated on a focused MQTT-native packet benchmark where broker-facing semantic hints are actually present.",
        "- Semantic-lite feature engineering remains conservative and does not claim full MQTT session-state reconstruction.",
        "- MQTT_UAD provides auxiliary semantic extractability and DoS sanity evidence only.",
        "",
        "## 5. What Claims the Paper Must Avoid",
        "",
        "- Do not call the packet semantic benchmark the main LOAO benchmark.",
        "- Do not imply that packet semantic evidence covers `scan_A`, `scan_sU`, or `sparta` under the frozen broker-facing definition.",
        "- Do not claim behavior-consistency gains across all attack families unless later biflow-main and packet-focused evidence both support that statement.",
        "- Do not describe the method as full session-state consistency or full MQTT protocol-state reconstruction.",
        "- Do not promote MQTT_UAD to the main benchmark.",
        "",
        "## Semantic-Lite Pipeline Status",
        "",
        "- The semantic-lite pipeline is preserved and re-situated rather than discarded.",
        "- Mainline use after cleanup: focused packet semantic benchmark on `normal + mqtt_bruteforce`.",
        "- Auxiliary use after cleanup: MQTT_UAD DoS semantic extractability and sanity checks.",
    ]
    write_text(REPORT_PATH, "\n".join(lines) + "\n")


def materialize_benchmark_tracks() -> None:
    """Create Phase 2.5 split artifacts, tables, logs, and cleanup report."""

    ensure_directory(MAIN_MANIFEST_DIR)
    ensure_directory(PACKET_MANIFEST_DIR)
    ensure_directory(REPO_ROOT / "outputs" / "logs")
    ensure_directory(REPO_ROOT / "outputs" / "tables")
    ensure_directory(REPO_ROOT / "reports")

    split_config = load_yaml_config(SPLIT_CONFIG_PATH)
    data_config = load_yaml_config(DATA_CONFIG_PATH)

    biflow_count_rows, biflow_log_lines, biflow_definition_rows = _materialize_main_biflow_track(
        split_config,
        data_config,
    )
    packet_count_rows, packet_log_lines, packet_definition_rows = _materialize_packet_semantic_track(
        split_config,
        data_config,
    )

    biflow_counts = pd.DataFrame(biflow_count_rows)
    packet_counts = pd.DataFrame(packet_count_rows)
    definition_rows = biflow_definition_rows + packet_definition_rows
    definition_table = pd.DataFrame(definition_rows)

    biflow_counts.to_csv(MAIN_COUNT_TABLE_PATH, index=False)
    packet_counts.to_csv(PACKET_COUNT_TABLE_PATH, index=False)
    definition_table.to_csv(DEFINITION_TABLE_PATH, index=False)

    log_lines = [
        "Phase 2.5 benchmark cleanup summary",
        "",
        "Historical packet LOAO manifests retained as historical artifacts only.",
        "Current benchmark tracks:",
        "- main_loao_biflow",
        "- focused_packet_semantic",
        *biflow_log_lines,
        *packet_log_lines,
    ]
    write_text(BENCHMARK_LOG_PATH, "\n".join(log_lines) + "\n")
    _write_benchmark_cleanup_report(
        biflow_counts=biflow_counts,
        packet_counts=packet_counts,
    )


def main() -> None:
    """CLI entry point for Phase 2.5 benchmark cleanup materialization."""

    materialize_benchmark_tracks()


if __name__ == "__main__":
    main()
