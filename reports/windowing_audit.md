# Windowing Audit

## Exact Window Key

`{broker_ip, peer_ip, peer_port, window_start_5s}`

## Broker-Facing Rule

Broker-facing direction was determined with the confirmed broker IP `192.168.1.7`.
Rows where `dst_ip == broker_ip` were treated as uplink; rows where `src_ip == broker_ip` were treated as downlink.
Rows involving neither endpoint as the broker were excluded from broker-facing window construction.
Rows where both endpoints matched the broker IP were logged as broker-facing ambiguity and excluded.

## Benign Rows Inside Attack Files

Main attack-window tables use only `is_attack == 1` rows from attack-family CSVs.
Benign broker-facing rows inside attack CSVs were separated into optional robustness pools and were not merged into the main benchmark tables.

## Fallback Logic

The fallback window key from `spec_v1.md` was not used because the broker IP was already confirmed and stable.

## Scenario-Level Window Counts

```text
       scenario          family  total_windows  mqtt_windows  non_mqtt_windows  attack_windows  normal_windows  dropped_windows
mqtt_bruteforce mqtt_bruteforce         865903        865824                79          865903               0                0
         normal          normal          79820         79791                29               0           79820                0
         scan_A          scan_A              0             0                 0               0               0             5340
        scan_sU         scan_sU              0             0                 0               0               0            15930
         sparta          sparta              0             0                 0               0               0            71626
```

## Ambiguous Cases

- `mqtt_bruteforce`: invalid timestamps=0, non-broker rows=34750, broker ambiguities=0, unexpected attack rows in normal file=0, out-of-order packet boundaries=0
- `normal`: invalid timestamps=0, non-broker rows=98993, broker ambiguities=0, unexpected attack rows in normal file=0, out-of-order packet boundaries=0
- `scan_A`: invalid timestamps=0, non-broker rows=47369, broker ambiguities=0, unexpected attack rows in normal file=0, out-of-order packet boundaries=0
- `scan_sU`: invalid timestamps=0, non-broker rows=42194, broker ambiguities=0, unexpected attack rows in normal file=0, out-of-order packet boundaries=0
- `sparta`: invalid timestamps=0, non-broker rows=19817081, broker ambiguities=0, unexpected attack rows in normal file=0, out-of-order packet boundaries=0
