# Benchmark Viability Cleanup

## 1. Why the Original Packet LOAO Benchmark Is Degenerate

- The frozen broker-facing 5-second packet-window definition produced valid main packet windows for `normal` and valid main attack windows for `mqtt_bruteforce`.
- Under that same frozen definition, `scan_A`, `scan_sU`, and `sparta` produced `0` main broker-facing packet attack windows.
- Because three of the four attack families vanish from the main packet table, the original packet LOAO setup cannot support a scientifically valid family-complete 4-fold unknown-rejection benchmark.
- The old packet LOAO manifests remain in the repository only as historical Phase 2 artifacts and must not be treated as current benchmark definitions.

## 2. Why Biflow Is Now the Family-Complete Main Benchmark

- The processed biflow matrices cover all five MQTT-IoT-IDS2020 scenarios, including all four attack families.
- The new `main_loao_biflow` track keeps the intended 4-fold LOAO unknown-rejection structure intact: `scan_A`, `scan_sU`, `sparta`, and `mqtt_bruteforce` can each be held out in turn.
- Split manifests reference the processed biflow parquet files while using aligned raw biflow endpoint metadata to keep endpoint groups separated across train, validation, and test partitions.

Current biflow LOAO count table:

```text
              fold_name  train_normal_count  train_seen_attack_count  validation_normal_count  validation_seen_attack_count  test_normal_count  test_heldout_attack_count  heldout_family
         holdout_scan_A               51604                    40877                    17201                         10217              17203                      19907          scan_A
        holdout_scan_sU               51604                    38855                    17201                          9712              17203                      22434         scan_sU
         holdout_sparta               51604                    45510                    17201                         11375              17203                      14116          sparta
holdout_mqtt_bruteforce               51604                    45167                    17201                         11290              17203                      14544 mqtt_bruteforce
```

## 3. Why Packet Semantic Evaluation Is Restricted to MQTT-Native Attack Evidence

- Packet-level semantic-lite features depend on broker-facing MQTT control hints such as message types and coarse connect/connack patterns.
- Those hints survive in the main packet tables for `mqtt_bruteforce`, but not for `scan_A`, `scan_sU`, or `sparta` under the frozen broker-facing definition.
- The `focused_packet_semantic` track is therefore restricted to `normal + mqtt_bruteforce` and is used only to test whether weak behavior-consistency hints help where MQTT-native packet evidence actually exists.
- MQTT_UAD remains auxiliary only for semantic extractability and DoS sanity support; it does not replace MQTT-IoT-IDS2020 as the primary dataset.

Current focused packet split count table:

```text
                  split_name  train_normal_count  train_mqtt_bruteforce_count  validation_normal_count  validation_mqtt_bruteforce_count  test_normal_count  test_mqtt_bruteforce_count                                                                                                                                                              notes
normal_mqtt_bruteforce_split               47885                       519301                    15966                            173564              15969                      173038 Focused MQTT-native packet benchmark only; excluded scan_A, scan_sU, and sparta because broker-facing main attack windows were absent under the frozen definition.
```

## 4. What Claims the Paper May Safely Make After This Cleanup

- The family-complete main benchmark for unknown rejection is MQTT-IoT-IDS2020 biflow LOAO.
- Weak MQTT behavior-consistency features can be evaluated on a focused MQTT-native packet benchmark where broker-facing semantic hints are actually present.
- Semantic-lite feature engineering remains conservative and does not claim full MQTT session-state reconstruction.
- MQTT_UAD provides auxiliary semantic extractability and DoS sanity evidence only.

## 5. What Claims the Paper Must Avoid

- Do not call the packet semantic benchmark the main LOAO benchmark.
- Do not imply that packet semantic evidence covers `scan_A`, `scan_sU`, or `sparta` under the frozen broker-facing definition.
- Do not claim behavior-consistency gains across all attack families unless later biflow-main and packet-focused evidence both support that statement.
- Do not describe the method as full session-state consistency or full MQTT protocol-state reconstruction.
- Do not promote MQTT_UAD to the main benchmark.

## Semantic-Lite Pipeline Status

- The semantic-lite pipeline is preserved and re-situated rather than discarded.
- Mainline use after cleanup: focused packet semantic benchmark on `normal + mqtt_bruteforce`.
- Auxiliary use after cleanup: MQTT_UAD DoS semantic extractability and sanity checks.
