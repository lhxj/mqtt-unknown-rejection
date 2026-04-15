"""Assemble frozen-scope biflow statistical baseline matrices."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd

from src.loaders.biflow_loader import BiflowLoader
from src.windowing.common import append_feature_coverage_rows, ensure_directory, load_yaml_config, write_text


REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "data" / "processed" / "biflow"
LOG_PATH = REPO_ROOT / "outputs" / "logs" / "biflow_sanity.log"
FEATURE_COVERAGE_PATH = REPO_ROOT / "outputs" / "tables" / "tab_feature_coverage.csv"


def _require_parquet_support() -> None:
    """Ensure parquet support is available before export."""

    if importlib.util.find_spec("pyarrow") is None:
        raise RuntimeError(
            "pyarrow is required to write parquet outputs for Phase 2. "
            "Install it before running src/features/stats_biflow.py."
        )


def _coverage_rows_for_biflow(frame: pd.DataFrame, allowed_columns: list[str]) -> list[dict[str, Any]]:
    """Create feature coverage rows for processed biflow features."""

    rows: list[dict[str, Any]] = []
    for column in allowed_columns:
        series = frame[column]
        rows.append(
            {
                "feature_name": column,
                "source_dataset": "mqtt_iot_ids2020",
                "source_granularity": "biflow",
                "non_null_rate": round(float(series.notna().mean()), 6),
                "non_zero_rate": round(float(series.fillna(0).ne(0).mean()), 6),
                "constant_flag": bool(series.fillna(0).nunique(dropna=False) <= 1),
                "allowed_for_classifier": True,
                "allowed_for_gate": False,
                "notes": "Processed biflow baseline feature from allowed_columns.",
            }
        )
    return rows


def assemble_biflow_matrices() -> dict[str, pd.DataFrame]:
    """Build clean biflow baseline matrices and write the required sanity log."""

    _require_parquet_support()
    ensure_directory(OUTPUT_DIR)
    ensure_directory(REPO_ROOT / "outputs" / "logs")
    ensure_directory(REPO_ROOT / "outputs" / "tables")

    feature_config = load_yaml_config(REPO_ROOT / "configs" / "features.yaml")
    allowed_columns = list(feature_config["biflow_stats"]["allowed_columns"])
    loader = BiflowLoader()

    outputs: dict[str, pd.DataFrame] = {}
    log_lines = ["Biflow sanity summary", ""]
    full_frames: list[pd.DataFrame] = []

    columns_to_load = list(
        dict.fromkeys(
            ["is_attack"] + allowed_columns
        )
    )

    for scenario in loader.available_scenarios():
        chunks: list[pd.DataFrame] = []
        raw_rows = 0
        retained_rows = 0
        benign_rows_excluded = 0
        for chunk in loader.iter_scenario(
            scenario,
            columns=columns_to_load,
            chunksize=200_000,
        ):
            raw_rows += len(chunk)
            chunk = chunk.copy()
            chunk["is_attack"] = pd.to_numeric(chunk["is_attack"], errors="coerce").fillna(0).astype(int)
            for column in allowed_columns:
                chunk[column] = pd.to_numeric(chunk[column], errors="coerce")

            if scenario == "normal":
                retained = chunk.loc[chunk["is_attack"] == 0, allowed_columns].copy()
            else:
                retained = chunk.loc[chunk["is_attack"] == 1, allowed_columns].copy()
                benign_rows_excluded += int((chunk["is_attack"] == 0).sum())

            retained_rows += len(retained)
            if retained.empty:
                continue

            retained.insert(0, "source_pool", "main")
            retained.insert(0, "unknown_capable", scenario != "normal")
            retained.insert(0, "attack_binary_label", 0 if scenario == "normal" else 1)
            retained.insert(0, "known_label", "normal" if scenario == "normal" else scenario)
            retained.insert(0, "family", "normal" if scenario == "normal" else scenario)
            retained.insert(0, "scenario", scenario)
            chunks.append(retained)

        scenario_frame = pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame(
            columns=[
                "scenario",
                "family",
                "known_label",
                "attack_binary_label",
                "unknown_capable",
                "source_pool",
                *allowed_columns,
            ]
        )
        output_path = OUTPUT_DIR / (
            "biflow_normal.parquet" if scenario == "normal" else f"biflow_{scenario}.parquet"
        )
        scenario_frame.to_parquet(output_path, index=False, engine="pyarrow")
        outputs[scenario] = scenario_frame
        full_frames.append(scenario_frame)

        log_lines.extend(
            [
                f"[{scenario}]",
                f"raw_rows={raw_rows}",
                f"retained_rows={retained_rows}",
                f"excluded_benign_rows_inside_attack_files={benign_rows_excluded}",
                f"output_path={output_path}",
                "",
            ]
        )

    full_frame = pd.concat(full_frames, ignore_index=True)
    coverage_rows = _coverage_rows_for_biflow(full_frame, allowed_columns)
    append_feature_coverage_rows(FEATURE_COVERAGE_PATH, coverage_rows)

    constant_features = [row["feature_name"] for row in coverage_rows if row["constant_flag"]]
    log_lines.append(
        f"constant_biflow_features={', '.join(constant_features) if constant_features else 'none'}"
    )
    write_text(LOG_PATH, "\n".join(log_lines) + "\n")
    return outputs


def main() -> None:
    """CLI entry point for biflow matrix assembly."""

    assemble_biflow_matrices()


if __name__ == "__main__":
    main()
