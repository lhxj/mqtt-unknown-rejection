# Go / No-Go Memo
**Project:** Unknown Attack Rejection via MQTT Behavior-Consistency for Edge Gateways  
**Version:** v1  
**Status:** Draft / To Be Filled After MVP Runs

---

## 1. Purpose

This memo records the current decision status of the project:

- **Go**
- **Conditional Go**
- **No-Go**

It must be written only after:
- main LOAO runs are complete,
- required ablations are complete,
- shortcut ablation is complete,
- edge replay profiling is complete.

This memo is the final decision artifact for whether the project proceeds to:
- full paper drafting,
- scope downgrade,
- or abandonment of the current claim.

---

## 2. Frozen Claim Under Evaluation

The claim being evaluated is:

> Weak MQTT behavior-consistency hints can improve unknown attack rejection over confidence-only baselines on a representative RISC-V edge-gateway prototype.

This memo must evaluate that exact claim.
Do not silently widen or narrow the claim here.

---

## 3. Decision

### Current verdict
- [ ] Go
- [ ] Conditional Go
- [ ] No-Go

### One-sentence conclusion
_Write one sentence here._

### Confidence
- [ ] High
- [ ] Medium
- [ ] Low

---

## 4. Evidence Summary

| Evidence Item | Status | Notes |
|---|---|---|
| Main benchmark completed |  |  |
| 4-fold LOAO completed |  |  |
| Confidence-only baseline completed |  |  |
| Biflow strong baseline completed |  |  |
| Joint gate completed |  |  |
| Semantic-only threshold completed |  |  |
| Shortcut ablation completed |  |  |
| MQTT_UAD DoS sanity check completed |  |  |
| Edge replay profiling completed |  |  |

---

## 5. Main Benchmark Summary

### 5.1 Primary dataset
- MQTT-IoT-IDS2020

### 5.2 Main granularity
- packet_features aggregated into 5-second windows

### 5.3 Strong statistical baseline
- biflow_features

### 5.4 Secondary dataset role
- MQTT_UAD used only for:
  - semantic extractability
  - DoS sanity check
  - appendix-level auxiliary evidence

---

## 6. Fold-Level Result Summary

| Fold | Held-out family | Best confidence-only H-score | Joint H-score | Delta | Unknown recall delta | Verdict |
|---|---|---:|---:|---:|---:|---|
| 1 | scan_A |  |  |  |  |  |
| 2 | scan_sU |  |  |  |  |  |
| 3 | sparta |  |  |  |  |  |
| 4 | mqtt_bruteforce |  |  |  |  |  |

### Narrative summary
_Write short interpretation here._

---

## 7. Required Ablation Summary

| Ablation | Completed? | Result summary | Supports main claim? |
|---|---|---|---|
| confidence-only |  |  |  |
| semantic-only |  |  |  |
| joint |  |  |  |
| shortcut ablation |  |  |  |

### RQ2 interpretation
Did the joint method outperform either component alone in a stable way?

_Write answer here._

---

## 8. Semantic-lite Feature Status

| Feature | Implemented? | Stable on main benchmark? | Helpful? | Keep / Downgrade / Postpone |
|---|---|---|---|---|
| reconnect_frequency |  |  |  |  |
| order_anomaly_ratio_lite |  |  |  |  |
| missing_handshake_ratio_lite |  |  |  |  |
| qos_mismatch_ratio_aux |  |  |  |  |
| keepalive_violation_count |  |  |  |  |

### Interpretation
- Which features actually contributed?
- Which features were too sparse or unstable?
- Does the behavior-consistency story still hold with the surviving features?

_Write summary here._

---

## 9. Shortcut and Leakage Assessment

### 9.1 Shortcut ablation verdict
- [ ] passed
- [ ] partially passed
- [ ] failed

### 9.2 What was removed
- raw IP identity fields
- raw MAC identity fields
- raw absolute time
- packet/frame order indices
- file/scenario identity fields
- protocol/proto fields
- labels

### 9.3 Post-ablation result
Did the main conclusion survive after removing shortcuts?

_Write summary here._

### 9.4 If failed
Explain whether the result was actually learning:
- scene identity,
- attacker endpoint identity,
- file-specific patterns,
- or other leakage.

_Write summary here._

---

## 10. Edge Replay Profiling Summary

### Platform
- Banana Pi BPI-F3 / SpacemiT K1
- representative resource-constrained RISC-V edge-gateway prototype

### Full chain measured
`pcap replay -> rebuild -> feature extraction -> inference -> rejection -> alerting`

### Runtime summary

| Metric | Value | Threshold | Pass? |
|---|---:|---:|---|
| Throughput |  |  |  |
| p50 latency |  |  |  |
| p95 latency |  | < 1 s |  |
| CPU usage |  |  |  |
| RAM usage |  | < 2 GB |  |
| Replay drop rate |  |  |  |
| Alert latency |  |  |  |

### Bottleneck diagnosis
Where is the dominant bottleneck?
- [ ] parser / rebuild
- [ ] feature extraction
- [ ] model inference
- [ ] I/O
- [ ] unknown / mixed

### Interpretation
_Write short summary here._

---

## 11. Success Criteria Check

### 11.1 Internal stretch goal
| Criterion | Status | Notes |
|---|---|---|
| avg U-Recall >= 0.65 |  |  |
| avg H-score >= 0.70 |  |  |
| joint gain over confidence-only >= 0.05 |  |  |
| held-out mqtt_bruteforce U-Recall gain >= 10 pts |  |  |
| known Macro-F1 drop <= 5 pts |  |  |
| edge p95 latency < 1 s |  |  |
| edge RAM < 2 GB |  |  |

### 11.2 Minimum continue-writing threshold
| Criterion | Status | Notes |
|---|---|---|
| stable positive joint gain |  |  |
| mqtt_bruteforce fold not worse |  |  |
| shortcut ablation story survives |  |  |
| end-to-end replay pipeline runs |  |  |

---

## 12. Failure / Downgrade Trigger Check

| Trigger | Hit? | Notes |
|---|---|---|
| avg U-Recall < 0.50 |  |  |
| avg H-score < 0.60 |  |  |
| joint gain < 0.03 |  |  |
| no positive gain on held-out mqtt_bruteforce |  |  |
| collapse after shortcut removal |  |  |
| replay pipeline cannot keep up |  |  |

---

## 13. Final Decision Logic

### If Go
Use when:
- joint gate shows stable gain,
- shortcut ablation does not break the story,
- edge replay pipeline runs end-to-end.

### If Conditional Go
Use when:
- the story is promising but one or more conditions remain unresolved,
- some metrics miss stretch targets but the minimum continue-writing threshold is met.

### If No-Go
Use when:
- gains disappear after shortcut removal,
- held-out mqtt_bruteforce does not benefit,
- or edge execution fails badly enough that RQ3 cannot be defended.

---

## 14. Required Claim Wording

### If Go
Use:
> Weak MQTT behavior-consistency improves unknown attack rejection over confidence-only baselines on a representative RISC-V edge-gateway prototype.

### If Conditional Go
Use:
> Weak MQTT behavior-consistency shows promising but conditional gains for unknown attack rejection, subject to shortcut-robustness and replay-stage efficiency.

### If No-Go
Use:
> The current frozen MVP does not yet support the intended unknown-rejection claim without further scope reduction.

---

## 15. Minimal Downgrade Path

If full frozen claim cannot be supported, the minimum downgrade is:

> Weak MQTT behavior-consistency hints for unknown attack rejection on a representative RISC-V edge gateway.

This downgrade keeps:
- MQTT
- unknown rejection
- edge gateway

and avoids returning to full session-state wording.

---

## 16. Final Recommendation

### Recommendation
_Write final recommendation here._

### Immediate next step
- [ ] proceed to full paper outline
- [ ] rerun selected ablations
- [ ] simplify semantic-lite extractor
- [ ] downgrade claim wording
- [ ] stop and reassess topic

### Notes for paper writing
_Write 3–5 bullet points here on what can safely be claimed in the paper._