# mqtt-unknown-rejection

Minimum-viable research codebase for:

**Unknown Attack Rejection via MQTT Behavior-Consistency for Edge Gateways**

## Project Scope

This repository implements the frozen MVP version of the project.

Current claim:

> Weak MQTT behavior-consistency hints can improve unknown attack rejection over confidence-only baselines on a representative RISC-V edge-gateway prototype.

This repository is **not** for full MQTT session-state reconstruction.  
The current scope is intentionally restricted to:

- MQTT
- unknown rejection
- lightweight tabular ML
- weak behavior-consistency
- edge-gateway replay profiling

## Datasets

### Primary dataset
**MQTT-IoT-IDS2020**

Used for:
- main family-complete benchmark via `biflow_features`
- 4-fold LOAO unknown rejection across all 4 attack families
- focused packet semantic benchmark via broker-facing 5-second packet windows on `normal + mqtt_bruteforce`
- biflow main-table results plus packet semantic support analysis

### Secondary dataset
**MQTT_UAD**

Used only for:
- semantic-field extractability checks
- DoS sanity check
- appendix-level auxiliary evidence

It must **not** replace the primary benchmark.

## Phase 2.5 Benchmark Cleanup

Phase 2 showed that the frozen broker-facing packet-window definition is not family-complete:

- `normal` produced valid main packet windows
- `mqtt_bruteforce` produced valid main packet attack windows
- `scan_A`, `scan_sU`, and `sparta` produced `0` main broker-facing packet attack windows

After this cleanup, the repository uses two explicit benchmark tracks:

- `main_loao_biflow`: the family-complete main benchmark for MQTT-IoT-IDS2020 unknown rejection
- `focused_packet_semantic`: a restricted MQTT-native packet benchmark for testing semantic-lite contribution where weak MQTT behavior hints actually exist

Packet semantic results must not be described as family-complete LOAO evidence.

## Repository Layout
```text
mqtt-unknown-rejection/
├── README.md
├── spec_v1.md
├── configs/
│   ├── data.yaml
│   ├── edge.yaml
│   ├── features.yaml
│   ├── gate.yaml
│   └── split.yaml
├── data/
│   ├── raw/
│   │   ├── mqtt_iot_ids2020/
│   │   └── mqtt_uad/
│   ├── interim/
│   └── processed/
├── src/
│   ├── loaders/
│   ├── windowing/
│   ├── features/
│   │   ├── stats_packet.py
│   │   ├── stats_biflow.py
│   │   └── semantic_lite.py
│   ├── splits/
│   ├── models/
│   │   └── train_lgbm.py
│   ├── rejection/
│   │   └── gate.py
│   ├── eval/
│   │   ├── metrics.py
│   │   └── loao_eval.py
│   └── edge/
│       └── replay_profile.py
├── outputs/
│   ├── tables/
│   ├── figures/
│   ├── logs/
│   └── checkpoints/
└── reports/
    ├── go_no_go_memo.md
    ├── shortcut_ablation.md
    └── whitelist_blacklist_enforcement.md
```
## Single Source of Truth

The repository follows this priority order:

1. **`spec_v1.md`**
   Frozen experiment contract. This is the authoritative source for:

   * scope
   * benchmark definition
   * LOAO protocol
   * semantic-lite feature policy
   * edge evaluation policy
   * downgrade triggers

2. **`configs/*.yaml`**
   Machine-readable experiment settings.

3. **`reports/*.md`**
   Execution evidence, compliance checks, and final decision artifacts.

If anything in code conflicts with `spec_v1.md`, the spec wins.

## Config Files

### `configs/data.yaml`

Defines:

* dataset roots
* main/auxiliary dataset roles
* selected granularity
* windowing policy
* broker-facing grouping rules

### `configs/features.yaml`

Defines:

* classifier whitelist
* global blacklist
* grouping-only fields
* semantic-lite inputs
* leakage control policy

### `configs/split.yaml`

Defines:

* `main_loao_biflow` for the family-complete main benchmark
* `focused_packet_semantic` for the restricted MQTT-native packet benchmark
* train/validation/test protocol per track
* historical packet LOAO artifacts as non-current references
* auxiliary dataset split usage

### `configs/gate.yaml`

Defines:

* confidence-only / semantic-only / joint modes
* rejection gate parameters
* threshold search policy
* success and failure criteria

### `configs/edge.yaml`

Reserved for:

* replay profiling
* throughput/latency measurement
* CPU/RAM logging
* stage-level timing

## Frozen Experiment Design

### Main task

**Known-class classification + unknown rejection**

### Main benchmark

* MQTT-IoT-IDS2020
* `biflow_features`
* 4-fold LOAO unknown rejection across `scan_A`, `scan_sU`, `sparta`, and `mqtt_bruteforce`

### Focused packet semantic benchmark

* MQTT-IoT-IDS2020
* 5-second broker-facing bidirectional endpoint windows
* restricted to `normal + mqtt_bruteforce`
* used to test semantic-lite contribution where MQTT-native packet evidence exists
* not valid as family-complete LOAO evidence

### Held-out families

* `scan_A`
* `scan_sU`
* `sparta`
* `mqtt_bruteforce`

### Frozen semantic-lite features

Only these three enter the MVP mainline:

* `reconnect_frequency`
* `order_anomaly_ratio_lite`
* `missing_handshake_ratio_lite`

Auxiliary only:

* `qos_mismatch_ratio_aux`

Postponed:

* `keepalive_violation_count`

### Main model

* LightGBM

### Rejection logic

* confidence-only
* semantic-only
* joint gate

Joint gate form:

`u = alpha * (1 - pmax) + beta * s_sem`

The biflow track is the family-complete main benchmark after Phase 2.5 cleanup.
The packet semantic track is a focused MQTT-native support benchmark and must be reported that way.

## Leakage and Shortcut Policy

The following must never enter the main classifier:

* labels (`is_attack`, `type`)
* raw IP fields
* raw MAC fields
* raw absolute timestamps
* `frame.number`
* file/scenario/fold identity
* protocol/proto fields
* any feature that directly reveals capture identity

These may only be used for:

* grouping
* window construction
* alignment
* reporting
* shortcut ablation

## Edge Evaluation Policy

The edge experiment must measure the full chain:

`pcap replay -> rebuild -> feature extraction -> inference -> rejection -> alerting`

Inference-only timing is not enough.

Platform wording must remain conservative:

**Banana Pi BPI-F3 / SpacemiT K1 is used as a representative resource-constrained RISC-V edge-gateway prototype.**

## Expected Outputs

### Tables

* `tab_field_whitelist_blacklist.csv`
* `tab_loao_main_results.csv`
* `tab_joint_vs_conf_vs_semantic.csv`
* `tab_mqtt_uad_extractability.csv`
* `tab_edge_runtime.csv`

### Figures

* `fig_pipeline.pdf`
* `fig_loao_hscore_urecall.pdf`
* `fig_joint_ablation.pdf`
* `fig_edge_latency_breakdown.pdf`

### Reports

* `reports/whitelist_blacklist_enforcement.md`
* `reports/shortcut_ablation.md`
* `reports/go_no_go_memo.md`

## Recommended Execution Order

### Phase 1

* verify dataset paths
* verify config files
* implement packet loader
* implement biflow loader
* enforce field blacklist/whitelist

### Phase 2

* implement 5-second windowing
* implement LOAO split logic
* run statistical baselines

### Phase 3

* implement 3 semantic-lite features
* run confidence-only / semantic-only / joint ablations

### Phase 4

* run MQTT_UAD extractability and DoS sanity check

### Phase 5

* run BPI-F3 replay profiling
* fill `go_no_go_memo.md`

## Data Path Notes

This repository expects:

* `data/raw/mqtt_iot_ids2020/`
* `data/raw/mqtt_uad/`

If your real datasets live elsewhere, use symbolic links instead of copying the full data.

Example:

```bash
cd data/raw
ln -s /absolute/path/to/MQTT-IoT-IDS2020/数据集 mqtt_iot_ids2020
ln -s /absolute/path/to/MQTT_UAD/数据集 mqtt_uad
```

## Naming Convention

Use:

`{dataset}_{granularity}_{split}_{model}_{gate}_{seed}`

Examples:

* `mqttids2020_packet_loao_lgbm_closed_seed1`
* `mqttids2020_packet_loao_lgbm_confgate_seed1`
* `mqttids2020_biflow_loao_lgbm_confgate_seed1`
* `mqttids2020_packet_loao_lgbm_jointgate_seed1`
* `mqttuad_dos_aux_semantic_extractability_seed1`
* `bpif3_replay_jointgate_run01`

## What Must Not Change

Do not:

* switch back to full session-state as the main claim
* replace LightGBM with deep models
* promote MQTT_UAD to the main benchmark
* let shortcut fields enter the main classifier
* report edge inference time alone as deployment evidence
* change the task from unknown rejection to ordinary closed-set classification

## Decision Rule

The repository exists to answer only three questions:

1. Does weak MQTT behavior-consistency provide a real unknown-rejection gain?
2. Does that gain survive shortcut removal?
3. Can the replay-to-alert chain run on a representative RISC-V edge prototype?

If yes, proceed to full paper writing.
If no, downgrade the claim before expanding the project.
