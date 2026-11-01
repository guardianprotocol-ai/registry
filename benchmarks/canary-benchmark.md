# Canary benchmark

Measured by `python3 benchmarks/canary_benchmark.py`. Do not type numbers into this file by hand.

Seed 20261031. 30 trials per scenario. Python 3.12.3. Commit `e1b0b93bdebf10fa6687e1a608a3fc75e5c8673d`. Rules fingerprint `dc406e8125eb`. Canaries armed, sensor in block mode. Elapsed 42.7 s.

The before column is the pre-fix matcher, scored on these same trials. It reproduces the published local run (1980/2100, 0/840, 150/1260, 2130/4200, benign 0/2100) when that check says yes: True.

The naive column is an exact substring of the plaintext value. It can only be computed by keeping the value. The sensor stores a salted digest, a case-folded digest, and the length.

The one-character near miss replaces the last character with a digit. The generator this suite started from appended "A" whenever the last character was not already "A". When that character was "a", the result was the same value under case folding, and a first run scored it as the only benign hit (1 of 2100). A case-only copy is a detection, not a false alarm, so the substitution was changed to a digit. That change does not draw from the seed. The attack strings are unchanged.

## Regression suite

| Slice | Trials | Sensor | Wilson 95% | Pre-fix matcher | Wilson 95% | Naive exact text | Wilson 95% |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Designed carriers | 2100 | 2100/2100 (100.0%) | [0.9982, 1.0000] | 1980/2100 (94.3%) | [0.9321, 0.9520] | 2100/2100 (100.0%) | [0.9982, 1.0000] |
| Formatting edges | 840 | 840/840 (100.0%) | [0.9954, 1.0000] | 0/840 (0.0%) | [0.0000, 0.0046] | 840/840 (100.0%) | [0.9954, 1.0000] |
| Encodings, including a split across two calls | 1260 | 1260/1260 (100.0%) | [0.9970, 1.0000] | 150/1260 (11.9%) | [0.1023, 0.1381] | 150/1260 (11.9%) | [0.1023, 0.1381] |
| All regression attacks | 4200 | 4200/4200 (100.0%) | [0.9991, 1.0000] | 2130/4200 (50.7%) | [0.4920, 0.5222] | 3090/4200 (73.6%) | [0.7222, 0.7488] |
| Benign, GP-0020 false alarms | 2100 | 0/2100 (0.0%) | [0.0, 0.0018] | 0/2100 | [0.0, 0.0018] | 0/2100 | [0.0, 0.0018] |

Value present in the evidence log: 0 of 4200 regression trials.

GP-0002, the built-in secret-shape rule, also fires on some of these fakes (AWS-shaped and `sk-` shaped). That is not a GP-0020 result. On the regression trials it fired 870 times. On the benign trials the sensor blocked 128 of 2100 for some other rule.

## By path

| Path | Sensor | Pre-fix | Naive |
| --- | --- | --- | --- |
| `msg_body_whole` | 210/210 | 210/210 | 210/210 |
| `msg_body_prose_space` | 210/210 | 210/210 | 210/210 |
| `env_assignment` | 210/210 | 180/210 | 210/210 |
| `http_query_local` | 210/210 | 180/210 | 210/210 |
| `http_post_body_local` | 210/210 | 210/210 | 210/210 |
| `bearer_header` | 210/210 | 210/210 | 210/210 |
| `file_write_inline` | 210/210 | 210/210 | 210/210 |
| `shell_curl` | 210/210 | 180/210 | 210/210 |
| `markdown_image` | 210/210 | 180/210 | 210/210 |
| `csv_row` | 210/210 | 210/210 | 210/210 |
| `prose_trailing_period` | 210/210 | 0/210 | 210/210 |
| `file_write_own_line` | 210/210 | 0/210 | 210/210 |
| `url_path_segment` | 210/210 | 0/210 | 210/210 |
| `quoted_colon_prefix` | 210/210 | 0/210 | 210/210 |
| `enc_base64` | 210/210 | 0/210 | 0/210 |
| `enc_hex` | 210/210 | 0/210 | 0/210 |
| `enc_percent_url` | 210/210 | 150/210 | 150/210 |
| `enc_reversed` | 210/210 | 0/210 | 0/210 |
| `enc_uppercase` | 210/210 | 0/210 | 0/210 |
| `enc_split_two_calls` | 210/210 | 0/210 | 0/210 |

## Held out

These transforms were excluded from the matcher on purpose, before this run's scores were known. A miss here is the limit, not a failure.

| Path | Sensor | Wilson 95% | Naive exact text |
| --- | --- | --- | --- |
| `holdout_zero_width` | 0/210 | [0.0, 0.018] | 0/210 |
| `holdout_base32` | 0/210 | [0.0, 0.018] | 0/210 |
| `holdout_split_reverse_order` | 0/210 | [0.0, 0.018] | 0/210 |
| `holdout_rot13` | 0/210 | [0.0, 0.018] | 0/210 |
| `holdout_ends_only` | 0/210 | [0.0, 0.018] | 0/210 |
| `holdout_gzip_base64` | 0/210 | [0.0, 0.018] | 0/210 |

Held out overall: 0/1260, Wilson 95% [0.0, 0.003].

## Other channels

| Path | Sensor | Wilson 95% | What it is |
| --- | --- | --- | --- |
| `dns_name_local` | 210/210 | [0.982, 1.0] | The value is a label in a name sent to 127.0.0.1. No packet is sent. |
| `omitted_from_arguments` | 0/210 | [0.0, 0.018] | The arguments do not contain the value. This is the network-edge gap. |

## Read alarm

GP-0007 when a registered value appears in a tool result.

- tainted_then_read: 210/210, Wilson 95% [0.982, 1.0]
- untainted_read: 0/210, Wilson 95% [0.0, 0.018]

## Latency

In process, one registered canary, arguments that do not contain it.

| Size | Bytes | Iters | inspect median us | inspect p95 us | match median us | match p95 us | naive median us |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ~1KB | 1146 | 2000 | 219.01 | 244.38 | 46.44 | 52.43 | 0.14 |
| ~100KB | 112550 | 2000 | 11153.71 | 11479.93 | 2913.58 | 3082.05 | 16.44 |

## End to end

Real proxy process in front of `sensor/tests/fake_server.py`. Judged from the lab server's sink file.

| Arm | Case | Trials | Reached sink | GP-0020 evidence | Median round trip ms |
| --- | --- | --- | --- | --- | --- |
| sensor | `e2e_http_post_body` | 20 | 0 | 20 | 0.711 |
| sensor | `e2e_send_message_trailing_period` | 20 | 0 | 20 | 0.66 |
| sensor | `e2e_split_in_order` | 20 | 0 (completing half 0) | 20 | 1.743 |
| sensor | `e2e_benign_send` | 20 | 20 | 0 | 0.963 |
| no_sensor | `e2e_http_post_body` | 20 | 20 | 0 | 0.466 |
| no_sensor | `e2e_send_message_trailing_period` | 20 | 20 | 0 | 0.413 |
| no_sensor | `e2e_split_in_order` | 20 | 0 (completing half 20) | 0 | 0.684 |
| no_sensor | `e2e_benign_send` | 20 | 20 | 0 | 0.359 |

## What this does not claim

- The calls are scripted. No model decided to send anything.
- A tool that sends the value on its own, without putting it in the arguments, is not seen. `omitted_from_arguments` measures that miss.
- One decode layer only. Compression, rot13, base32, and a second encoding are held out.
- Halves are joined in order, and only with the immediately previous tool call. An intervening call drops the fragment. The first half is forwarded, because a digest cannot be compared with a prefix. Reverse order is held out.
- A window is taken only inside a token of at most 256 characters. A value glued into a longer blob is missed.
- Case folding matches a copy that differs only by case. A one-character change does not. An entry written before the fold digest was added still matches exact text only.
- Values shorter than 12 characters, and values containing spaces, are refused at registration.
- GP-0020's corpus false-alarm field is a different measurement, from `corpus/benign/`, and is left at its own number.

## Reproduce

```bash
python3 benchmarks/canary_benchmark.py --seed 20261031 --trials 30 --e2e-trials 20 --latency-iters 2000
```
