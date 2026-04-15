# spec_v1.md

# Unknown Attack Rejection via MQTT Behavior-Consistency for Edge Gateways

**Frozen Execution Specification v1**

## Document Status

**Status:** Frozen MVP Specification
**Version:** v1
**Purpose:** Execution handoff for Codex and internal experiment governance
**Scope:** Minimum viable validation for a submission-oriented ICICS-style paper under a constrained timeline
**Phase 2.5 Cleanup Note:** benchmark viability cleanup applied; the family-complete main benchmark is biflow-based and the packet semantic benchmark is explicitly restricted to `normal + mqtt_bruteforce`

---

## 1. Background and Motivation

This project targets **MQTT / IoT / Industrial IoT security** and investigates whether **weak MQTT behavior-consistency hints** can improve **unknown attack rejection** when combined with a lightweight tabular classifier, while remaining deployable on a **representative resource-constrained RISC-V edge-gateway prototype**. The original project framing used the dual phrase “session-state/behavior consistency,” but the current uploaded evidence shows that the available main benchmark does not reliably support full session-state reconstruction at the field level. Therefore, this specification freezes the claim at the **behavior-consistency** level.  

The current project should be treated as **Conditional Go**, not unconditional greenlight. The Pro assessment explicitly recommends a small, hard, execution-oriented path rather than a larger “full session-state consistency” claim, especially under the current timeline pressure.

---

## 2. Frozen Core Claim

The project claim is frozen as follows:

**Weak MQTT behavior-consistency hints can improve unknown attack rejection over confidence-only baselines on a representative RISC-V edge-gateway prototype.**

This means:

* the paper is **not** positioned as a full MQTT protocol-state reconstruction paper;
* the paper is **not** centered on deep models or open-set theory novelty;
* the paper is centered on a **small but defensible combination** of:

  * lightweight tabular ML,
  * weak protocol/behavior consistency,
  * unknown rejection,
  * edge-gateway feasibility.

This claim is aligned with the uploaded project description and the Pro review, and is also consistent with the actual field support observed in MQTT-IoT-IDS2020 and MQTT_UAD.  

---

## 3. Research Questions

The project retains the following three research questions, but interprets them under the frozen behavior-consistency scope.

### RQ1

Can MQTT **behavior-consistency** features improve unknown-attack rejection over generic traffic-statistics features, especially for MQTT-native attacks?

### RQ2

Does combining classifier confidence with a behavior-consistency score produce more stable unknown rejection than either component alone?

### RQ3

Can the frozen method run in real time on a **representative resource-constrained RISC-V edge-gateway prototype**?

These research questions are preserved from the uploaded project description, but the first one must now be read as **behavior-consistency**, not full session-state consistency.

---

## 4. Dataset Roles

### 4.1 Primary Dataset: MQTT-IoT-IDS2020

**MQTT-IoT-IDS2020** is frozen as the **primary dataset** for the benchmarked experiments. It provides five recorded scenarios, including one normal scenario and four attack scenarios: aggressive scan, UDP scan, Sparta SSH brute-force, and MQTT brute-force. It also provides three feature granularities: `packet_features`, `uniflow_features`, and `biflow_features`. 

After the Phase 2.5 benchmark cleanup, MQTT-IoT-IDS2020 supports two distinct tracks:

* a **family-complete main benchmark** using `biflow_features` for 4-fold LOAO unknown rejection across all four attack families;
* a **focused packet semantic benchmark** using broker-facing packet windows only for `normal + mqtt_bruteforce`.

The main reason it is selected as the primary dataset is **not** that it has the richest MQTT semantics. It is selected because it naturally supports a family-based unknown-rejection story, while still exposing packet-level MQTT fields for a narrower semantic-lite analysis where those fields actually yield viable attack windows. 

### 4.2 Secondary Dataset: MQTT_UAD

**MQTT_UAD** is frozen as the **secondary dataset**. It must only be used for:

* verifying whether the proposed MVP semantic features are actually extractable from public packet-level fields;
* conducting a small external sanity check, primarily in the **DoS** file;
* supporting appendix-level or auxiliary evidence about MQTT protocol-level field availability.

MQTT_UAD contains three labeled CSV files, all sharing the same 67-field schema, and includes substantially richer MQTT fields such as `mqtt.clientid`, `mqtt.msgtype`, `mqtt.qos`, `mqtt.topic`, `mqtt.kalive`, `mqtt.msgid`, `mqtt.conflag.*`, and `mqtt.conack.*`. However, its file structure does not directly map to the same family-based benchmark role required for the main LOAO experiment.  

---

## 5. Dataset Granularity Freeze

### 5.1 Main Family-Complete Benchmark Granularity

The family-complete main benchmark must use **MQTT-IoT-IDS2020 biflow_features**.

This choice is mandatory after the Phase 2 packet-window viability check. The frozen broker-facing packet-window definition produced valid main attack windows for `mqtt_bruteforce`, but yielded **0 main broker-facing attack windows** for `scan_A`, `scan_sU`, and `sparta`. Therefore the packet-window path cannot support the intended family-complete 4-fold LOAO benchmark without redefining the sample unit, which this project must not do silently.

### 5.2 Focused Packet Semantic Benchmark Granularity

The focused packet semantic benchmark may use **MQTT-IoT-IDS2020 packet_features**, aggregated into fixed broker-facing windows, but it is restricted to **`normal + mqtt_bruteforce`**.

This focused packet track exists because only the packet-level CSVs expose MQTT fields such as:

* `mqtt_messagetype`
* `mqtt_messagelength`
* `mqtt_flag_qos`
* `mqtt_flag_clean`
* `mqtt_flag_uname`
* `mqtt_flag_passwd`
* `mqtt_flag_willflag`

These packet-level fields are weak but still sufficient to support a **behavior-consistency** interpretation. By contrast, `uniflow_features` and `biflow_features` are mostly statistical and do not carry the deeper MQTT protocol fields needed for semantic-lite feature construction. 

Packet semantic results must **not** be framed as family-complete LOAO evidence. Their purpose is to test whether weak behavior-consistency hints add value where MQTT-native packet evidence actually exists.

---

## 6. Attack Family Mapping

For the purposes of the frozen benchmark, the four attack families in MQTT-IoT-IDS2020 are defined as:

* `scan_A`
* `scan_sU`
* `sparta`
* `mqtt_bruteforce`

`normal.csv` is frozen as the **primary normal source**.

The main protocol must **not** mix benign rows embedded inside attack files into the core main table. Those rows may be revisited later in a robustness analysis, but not in the first frozen main result set. This reduces file-level contamination and keeps the main story aligned with family holdout rather than scenario memorization. 

---

## 7. Task Definition

The task is frozen as:

**known-class classification + unknown rejection**

where:

* **known classes** = `normal + seen attack families`
* **unknown class** = the held-out attack family in the current LOAO fold

This is **not** closed-set multiclass classification.
It is also **not** anomaly detection in the pure one-class sense.
It is a selective classification / rejection setting with family holdout.

---

## 8. Windowed Sample Construction

### 8.1 Primary Sample Unit

The packet semantic sample unit is frozen as a:

**5-second broker-facing bidirectional endpoint window**

The primary key should be defined as:

`{broker_ip, peer_ip, peer_port, window_start_5s}`

where `window_start_5s` is the floor of time to the nearest 5-second boundary.

### 8.2 Fallback Rule

If broker identity cannot be stably configured from the data pipeline, the fallback key is:

`{sorted(endpoint_pair), dominant_service_port, direction_tag, window_start_5s}`

This fallback exists only to avoid engineering deadlock. It must not cause the sample definition to drift into arbitrary connection grouping.

### 8.3 ClientID Policy

`clientID` is **not required** in the main experiment.
If `mqtt.clientid` is visible in MQTT_UAD, it may be used for **secondary sanity checks only**. It must not redefine the primary sample unit for the main benchmark.

This rule is necessary because the uploaded field summaries show that clientID-like fields are sparse or absent in the main benchmark. 

### 8.4 Viability Constraint

Under the frozen broker-facing packet-window definition, the resulting main attack-window coverage is viable for `mqtt_bruteforce` but not for `scan_A`, `scan_sU`, or `sparta`. For that reason, the packet path is restricted to the focused MQTT-native semantic benchmark and must not be used as the family-complete main benchmark.

---

## 9. Field Policy

### 9.1 Classifier Blacklist

The following fields must **never** enter the main classifier:

* `is_attack`
* `type`
* raw source/destination IP addresses
* raw MAC addresses
* raw absolute timestamps
* `frame.number`
* `protocol` / `proto`
* file name
* scenario name
* fold identifier
* any directly derived scene-identity feature

These fields may only be used for grouping, window construction, filtering, leakage analysis, or reporting.

This restriction is mandatory because the uploaded probe report explicitly shows that the attacker IP `192.168.2.5` is easy to localize in MQTT-IoT-IDS2020, and because the original MQTT-IoT-IDS2020 paper explicitly removed source/destination IP, protocol, and MQTT flags to avoid specific-feature influence. 

### 9.2 Allowed Statistical Features

The main classifier may use only aggregated traffic statistics such as:

* packet count
* byte count
* inter-arrival statistics
* packet-length statistics
* directional totals
* flag-count summaries
* biflow forward/backward statistics for the biflow baseline

### 9.3 Allowed Semantic-lite Inputs

For MQTT-IoT-IDS2020, the semantic-lite extractor may use:

* `mqtt_messagetype`
* `mqtt_messagelength`
* `mqtt_flag_clean`
* `mqtt_flag_qos`
* `mqtt_flag_uname`
* `mqtt_flag_passwd`
* `mqtt_flag_willflag`

For MQTT_UAD auxiliary checks, the extractor may additionally use:

* `mqtt.msgtype`
* `mqtt.qos`
* `mqtt.topic`
* `mqtt.kalive`
* `mqtt.msgid`
* `mqtt.clientid`
* `mqtt.conflag.*`
* `mqtt.conack.*`

These field lists are grounded in the uploaded field dictionaries and schema summaries.  

---

## 10. Semantic-lite Feature Set

Only the following three semantic-lite features are allowed in the frozen MVP packet semantic benchmark and auxiliary semantic checks.

### 10.1 `reconnect_frequency`

A window-level count or normalized rate of repeated connection-initiation behavior within a short period.

This is the most stable semantic-lite feature in the current data setting and should be treated as the highest-priority weak-behavior feature. The MVP feature document also identifies it as one of the most worth keeping.

### 10.2 `order_anomaly_ratio_lite`

A coarse protocol-order anomaly score based on window-level message-type sequence hints, rather than full state-machine reconstruction.

Examples include:

* business/control activity before any connect-like event,
* suspicious repetition or jumps in control-type order,
* unexpected local transitions among connection-relevant message types.

This is the feature closest to the original “consistency” story, but it must remain a lite, coarse implementation.

### 10.3 `missing_handshake_ratio_lite`

A simplified handshake incompleteness score, restricted to the most feasible connect/ack-like patterns observable in the available data.

It must not expand into full ACK-chain reconstruction or full MQTT transaction recovery.

### 10.4 Auxiliary-Only Features

`qos_mismatch_ratio` may be implemented only as an auxiliary feature on **MQTT_UAD DoS**.
`keepalive_violation_count` is postponed and must not enter the MVP mainline.

This exact keep/downgrade/postpone structure is consistent with the uploaded MVP feature draft and the Pro review. 

---

## 11. Split Protocol

### 11.1 Family-Complete Main Benchmark

The family-complete main benchmark must use **4-fold leave-one-attack-family-out (LOAO)** on **MQTT-IoT-IDS2020 biflow_features**:

* Fold 1: hold out `scan_A`
* Fold 2: hold out `scan_sU`
* Fold 3: hold out `sparta`
* Fold 4: hold out `mqtt_bruteforce`

For each fold:

* **Train** on `normal + 3 seen attack families`
* **Validate** only on splits derived from the seen-family side
* **Test** on the held-out attack family plus normal test windows

Threshold parameters (`alpha`, `beta`, `tau`) must be tuned **only** on seen-family validation. The held-out family must remain unseen until final evaluation.

### 11.2 Focused Packet Semantic Benchmark

The packet semantic benchmark must use a **train / validation / test** split over **MQTT-IoT-IDS2020 broker-facing packet windows** restricted to:

* `normal`
* `mqtt_bruteforce`

This packet split is used only to study semantic-lite contribution where weak MQTT behavior hints actually exist. It must **not** be reported as family-complete LOAO evidence, and it must **not** be generalized to `scan_A`, `scan_sU`, or `sparta` without new packet-window evidence.

---

## 12. Models and Baselines

### 12.1 Main Model

The main classifier is frozen as **LightGBM**.

The main reason is not theoretical optimality but execution reality: the current topic needs a lightweight, reproducible, tabular baseline with low engineering overhead and plausible edge deployment characteristics.

### 12.2 Rejection Gate

The rejection score is frozen as:

`u = alpha * (1 - pmax) + beta * s_sem`

where:

* `pmax` = maximum predicted class confidence proxy from the classifier
* `s_sem` = aggregated semantic-lite score

Decision rule:

* if `u > tau`, output `unknown`
* otherwise, output the predicted known class

### 12.3 Baseline Set

The frozen baseline set is:

1. **Biflow stats + LightGBM hard classification on the family-complete main LOAO benchmark**
2. **Biflow stats + LightGBM + confidence-only threshold on the family-complete main LOAO benchmark**
3. **Packet-window stats + semantic-lite gate analysis on the focused `normal + mqtt_bruteforce` packet benchmark**
4. **Semantic-lite rule-only threshold on the focused packet benchmark**

However, execution priority is not uniform. The first three must be run first. The semantic-only baseline should be treated as lower-priority and should not block the main MVP path. This adjustment preserves the scientific comparison structure while reflecting time constraints.

---

## 13. Required Ablations

The following ablations are mandatory:

* **confidence-only**
* **semantic-only**
* **joint**

These ablations directly answer RQ2 and are necessary to support any paper claim about whether behavior-consistency is actually helping beyond classifier confidence.

A **shortcut ablation** is also mandatory. The project must explicitly report whether its gains survive after removing raw endpoint identity, raw absolute time, and other scene-identity shortcuts from the classifier path.

---

## 14. Metrics

The frozen main metrics are:

* `Macro-F1` on known classes
* `K-Acc` (known-class accuracy)
* `U-Recall` (unknown recall)
* `False-Unknown Rate`
* `H-score`

The frozen edge metrics are:

* throughput
* p50 latency
* p95 latency
* CPU usage
* RAM usage
* replay drop rate
* alert output latency

The edge evaluation must measure the **whole chain**, not inference alone. This requirement is consistent with the uploaded platform note and Pro review, both of which emphasize that the bottleneck is more likely to be in parsing, feature extraction, and I/O than in the LightGBM model itself. 

---

## 15. Success Criteria

### 15.1 Internal Stretch Goal

The internal target is:

* average `U-Recall >= 0.65`
* average `H-score >= 0.70`
* joint gate improves over confidence-only by at least `0.05` H-score
* held-out `mqtt_bruteforce` fold improves `U-Recall` by at least 10 percentage points
* known-class `Macro-F1` drop is no more than 5 percentage points
* replay throughput is sustainable on BPI-F3/K1
* p95 latency per window is below 1 second
* RAM usage stays below 2 GB

### 15.2 Minimum Continue-Writing Threshold

The project may continue to full-paper drafting if:

* joint gate shows a **stable positive gain** over confidence-only;
* the held-out `mqtt_bruteforce` fold is not worse than confidence-only;
* the story does not collapse after shortcut ablation;
* the replay pipeline can run end-to-end on BPI-F3/K1.

These minimum criteria are more realistic than treating the internal stretch target as the only definition of success. The Pro memo supports a Conditional Go rather than a binary all-or-nothing standard.

---

## 16. Failure and Downgrade Triggers

Any of the following triggers a required downgrade:

1. average `U-Recall < 0.50` or `H-score < 0.60`
2. joint gate gain over confidence-only is less than `0.03`
3. held-out `mqtt_bruteforce` fold shows no positive gain
4. performance collapses after shortcut removal
5. parser + feature pipeline cannot keep up with replay on BPI-F3/K1

If downgrade is triggered, the claim must be reduced to:

**Weak MQTT behavior-consistency hints for unknown attack rejection on a representative RISC-V edge gateway.**

This downgrade keeps the three non-negotiable storyline anchors intact:

* MQTT
* unknown rejection
* edge gateway

---

## 17. Edge Evaluation Freeze

The platform role is frozen as:

**representative resource-constrained RISC-V edge-gateway prototype**

The following statements are safe in the paper:

* BPI-F3 is used as a representative resource-constrained RISC-V edge-gateway prototype.
* The board provides dual-GbE, an octa-core RISC-V CPU, and up to 16 GB LPDDR4, sufficient for lightweight parsing, feature extraction, and tabular ML inference.
* K1 support for modern RISC-V features makes it relevant for edge evaluation.

The following statements are unsafe and must be avoided:

* BPI-F3 represents all industrial gateways.
* The results prove industrial deployment readiness.
* 2.0 TOPS directly benefits the method, unless that path is actually used.
* The experiment represents inline production deployment.

These platform constraints are already documented in the uploaded platform note and must be followed exactly.

The edge measurement chain must be:

`pcap replay -> rebuild -> feature extraction -> inference -> rejection -> alerting`

---

## 18. Deliverables

The frozen minimum outputs are:

### Tables

* `tab_field_whitelist_blacklist.csv`
* `tab_main_benchmark_definition.csv`
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

* `reports/whitelist_blacklist.md`
* `reports/benchmark_viability_cleanup.md`
* `reports/shortcut_ablation.md`
* `reports/go_no_go_memo.md`

### Code Modules

* loader
* windower
* semantic-lite extractor
* LightGBM training/evaluation
* open-set evaluator
* replay profiler

---

## 19. Repository Skeleton

mqtt-unknown-rejection/
├── configs/
│   ├── data.yaml
│   ├── features.yaml
│   ├── split.yaml
│   ├── gate.yaml
│   └── edge.yaml
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
├── reports/
│   ├── whitelist_blacklist_enforcement.md
│   ├── shortcut_ablation.md
│   └── go_no_go_memo.md
├──README.md
├──spec_v1.md

---

## 20. Naming Convention

Use:

`{dataset}_{granularity}_{split}_{model}_{gate}_{seed}`

Examples:

* `mqttids2020_packet_loao_lgbm_closed_seed1`
* `mqttids2020_packet_loao_lgbm_confgate_seed1`
* `mqttids2020_biflow_loao_lgbm_confgate_seed1`
* `mqttids2020_packet_loao_lgbm_jointgate_seed1`
* `mqttuad_dos_aux_semantic_extractability_seed1`
* `bpif3_replay_jointgate_run01`

---

## 21. What Must Not Change

Codex must not:

* change the topic
* reintroduce full session-state as the main claim
* add new datasets
* replace LightGBM with deeper models
* promote MQTT_UAD to the main benchmark
* allow shortcut fields into the main classifier
* report inference-only edge numbers without parser/feature/I/O stages

---

## 22. Final Execution Interpretation

This specification should be interpreted as a **frozen MVP execution contract**.
Its purpose is not to maximize model performance.
Its purpose is to determine, under constrained time, whether:

1. weak MQTT behavior-consistency provides a real and reproducible unknown-rejection gain,
2. that gain survives shortcut removal, and
3. the full replay-to-alert chain is plausible on a representative RISC-V edge prototype.

If these three conditions hold, the project proceeds to full-paper writing.
If they do not, the claim must be further downgraded rather than expanded.
