https://www.kaggle.com/datasets/f67daffac11306b7c7a2757c58dccd0052fc7c58e7d2c5800909ca4ed2bbc945



# NSFNET + Ryu + ENAS/SD-CGAN: full issue history and current blocker

Project: `EfficientNAS_SDCGAN_Notebooks` — NSFNET Mininet topology, Ryu SDN controller
running an ENAS-searched SD-CGAN DDoS detector, entropy-weighted routing as mitigation.
Files touched so far: `ryu_ids_controller.py` and `tranalyzer_watcher.py` only. Offline
training notebooks/artifacts were explicitly left untouched throughout.

## Issue 1 — Accuracy/precision/recall/F1/ROC always empty in `/ids/metrics`

**Symptom:** `entropy_run.csv` showed `detection_count` and `attack_count` climbing into
the tens of thousands, but `labeled_flows` stuck at 0 on every row, so
`accuracy_percent`/`precision_percent`/`recall_percent`/`f1_score_percent`/`roc_auc` were
always null/empty.

**Root cause:** the native OpenFlow-stats detection path (`flow_stats_reply_handler` →
`_detect`) never attached a `ground_truth`. Only the external `tranalyzer_watcher.py`
running with `--label-by-ip` could supply one via `/ids/flow`. If that watcher wasn't
running, the controller had no way to score its own accuracy.

**Fix applied:** added `_auto_ground_truth()` to `ryu_ids_controller.py`, using the same
h1–h3=attack / h4–h6=normal convention as the watcher, applied automatically to every
detection path (native stats and REST) unless an explicit label is already present.
Configurable via env vars: `SDN_AUTO_LABEL_BY_IP` (default `1`), `SDN_ATTACK_IPS`
(default `10.0.0.1,10.0.0.2,10.0.0.3`), `SDN_NORMAL_IPS` (default
`10.0.0.4,10.0.0.5,10.0.0.6`).

## Issue 2 — Mitigation not actually mitigating

**Symptom:** huge `attack_count` in the CSV, but attacker traffic was only ever
rerouted, never blocked, even when it should have been.

**Root cause (two compounding bugs):**
1. `SDN_BLOCK_ATTACKS` defaulted to `"0"` — hard blocking was off unless explicitly
   enabled.
2. Even with blocking enabled, `block_threshold` defaulted to **0.995**, but the
   trained detector's own decision threshold (from `detection_config.pkl`) is **0.5**.
   A flow already classified as an attack almost never cleared that 0.995 bar, so
   blocking essentially never fired.

**Fix applied:**
- `SDN_BLOCK_ATTACKS` now defaults to `"1"`.
- `SDN_BLOCK_THRESHOLD` now defaults to the detector's own threshold (0.5), so any
  detected attack is eligible to be blocked unless you deliberately raise the bar.
- Added a mitigation-penalty term wired into `_edge_cost()` (entropy/congestion/learned
  modes): links currently carrying traffic from a flagged source get an added cost
  proportional to that source's share of the link's recent traffic, so rerouting
  actively avoids attacker-heavy paths instead of a no-op delete/reinstall of the same
  route. Decays after `SDN_SUSPICION_DECAY_SECONDS` (default 30s).
- Exposed all of this in `GET /ids/status` under a `"mitigation"` block for visibility.

## Issue 3 — Spoofed source IPs defeat both labeling and blocking

**Symptom:** user is intentionally spoofing attack source IPs (e.g.
`hping3 --rand-source`), which — as expected — breaks anything keyed on `ipv4_src`.

**Root cause:** both fixes above (and the original blocking logic) trusted `ipv4_src`.
Under full spoofing that field is attacker-controlled and meaningless: `_auto_ground_truth`
couldn't match it to a known host, and the block condition `src_ip in HOST_IP_TO_SWITCH`
was essentially always false, so hard blocking silently never fired.

**Fix applied:** added physical-origin tracking, since the one thing spoofing can't
fake is which switch port a packet actually arrived on:
- `packet_in_handler` now caches `(src_ip, dst_ip) -> (true_ingress_dpid, timestamp)`
  the moment a new flow is first seen — this always fires at the true ingress switch,
  because `_install_path` proactively installs the same match at every hop, so no
  downstream switch ever sees a table-miss for the same flow.
- New `_physical_origin_switch(src_ip, dst_ip)` helper resolves that cache (with a TTL
  matched to the flow's own 15s idle-timeout, `SDN_FLOW_ORIGIN_TTL_SECONDS`, default 30s).
- `_auto_ground_truth` falls back to this physical origin when the IP doesn't match a
  known host directly.
- `_mitigate_attack`'s hard block now matches on `in_port=HOST_PORT` at the resolved
  origin switch instead of `ipv4_src=<spoofed value>` — this drops all traffic from that
  physical host for the block window, which is also just the correct way to block a
  spoofing attacker.
- Suspicion tracking / link-contribution accounting for the reroute-cost penalty (Issue
  2) was re-keyed from raw `src_ip` to the same physical-origin identity, since under
  spoofing every packet has a different "src_ip" and the old keying produced a firehose
  of single-use, non-overlapping entries.
- Added periodic cache pruning (`flow_origin`, `suspicious_sources`) in the monitor loop
  to avoid unbounded growth under a sustained fully-randomized-source flood.

## Issue 4 — Need to also test "attack launched from a currently-trusted host"

**Symptom:** user wants to test both (a) normal case, attacker = h1/h2/h3 (works via the
static convention), and (b) attack traffic launched from h4/h5/h6 (hosts the static
convention labels as NORMAL) to see how detection/mitigation behaves against a host not
assumed to be malicious — without spoofing, without restarting Ryu, and without
permanently changing the IP-role convention.

**Fix applied:** added a dynamic per-IP ground-truth override to `ryu_ids_controller.py`:
- `self.label_overrides: Dict[str, Tuple[int, float]]` — ip → (role, expiry).
- `set_label_override(ip, role, duration_seconds)` / `clear_label_override(ip)` /
  `list_label_overrides()` methods.
- New REST endpoints: `POST /ids/label_override` (`{"ip", "role", "duration_seconds"}`),
  `GET /ids/label_override`, `DELETE /ids/label_override?ip=...`.
- Override is checked **before** the static IP table and before physical-origin
  fallback in `_auto_ground_truth`, and — critically — before an explicit
  `ground_truth` supplied in a REST payload in `detect_rest_payload`, so it also wins
  over `tranalyzer_watcher.py --label-by-ip` if that's running concurrently (otherwise
  the watcher would silently re-assert the static label and cancel the override out).
- Surfaced under `active_overrides` in `GET /ids/status`.

**Companion fix in `tranalyzer_watcher.py`:** the watcher used to print `gt=`/`ok=` in
its terminal output using its own locally-computed static-table guess, computed before
it even sent the request — so it never reflected an active override. Changed it to read
`result.get("ground_truth", ...)` from the controller's response instead (which already
reflects override / physical-origin / static resolution), falling back to the local
guess only if an older controller doesn't echo that field back.

## Issue 5 (CURRENT, UNRESOLVED) — REST API suddenly returning nothing

**Symptom:**
```
curl -s http://127.0.0.1:8080/ids/status | python3 -m json.tool
Expecting value: line 1 column 1 (char 0)

curl -s http://127.0.0.1:8080/ids/metrics | python3 -m json.tool
Expecting value: line 1 column 1 (char 0)
```
Both endpoints return an empty body, so `json.tool` has nothing to parse. This error is
about `json.tool` receiving zero bytes, not about malformed JSON.

**Working theory:** `curl -s` suppresses BOTH the progress meter and curl's own error
messages, so a failed connection (nothing listening on 8080, `ryu-manager` crashed or
never started/finished starting, etc.) looks identical to "got empty JSON" instead of
showing a clear connection error.

**Checked so far and ruled out:**
- The patched `ryu_ids_controller.py` compiles cleanly (`python3 -m py_compile`), so
  this is not a syntax error in the file.
- No duplicate/conflicting `@route(...)` names across the whole file, including the new
  `/ids/label_override` endpoints (GET/POST/DELETE on the same path, distinct route
  names) — this matches the existing pattern already used elsewhere in the file (e.g.
  `/ids/evaluation` vs `/ids/evaluation/reset`), so it's not expected to be a
  registration conflict either, though this couldn't be verified by actually running
  `ryu-manager` since `ryu` isn't installed in the sandbox used to make these patches.

**Not yet checked (next steps for the user):**
1. Is `ryu-manager` actually still running? `ps aux | grep ryu-manager`. If it crashed,
   there should be a Python traceback printed in that terminal — scroll up and check it.
2. Is anything listening on 8080 at all? `sudo ss -ltnp | grep 8080`.
3. Re-run with `-v` instead of `-s` to see the real error instead of an empty body:
   `curl -v http://127.0.0.1:8080/ids/status`.
4. Restart cleanly and watch the full startup log for a traceback before/instead of the
   expected `"ENAS/SD-CGAN loaded: ..."` line:
   ```bash
   cd ~/EfficientNAS_SDCGAN_Notebooks
   ryu-manager --ofp-tcp-listen-port 6633 ryu_ids_controller.py
   ```
5. Confirm Mininet/OVS wasn't reset (`sudo mn -c`) in a way that also disrupted the
   controller process or its OpenFlow connections.

**Still needed from the user to diagnose further:** the output of `curl -v ...` and
whatever is printed in the `ryu-manager` terminal (including any traceback).

## Current file state

- `ryu_ids_controller.py` — patched with all fixes from Issues 1–4. Offline
  training/preprocessing code and notebooks untouched.
- `tranalyzer_watcher.py` — patched with the display fix from Issue 4's companion fix.
- `README_EXECUTION_RESULTS.md` — updated with the new env vars, new mitigation
  mechanisms, and new `/ids/status` fields from Issues 1–2.

## Key env vars introduced (all optional, sensible defaults applied)

| Env var | Default | Purpose |
|---|---|---|
| `SDN_AUTO_LABEL_BY_IP` | `1` | controller self-labels detections via static IP convention |
| `SDN_ATTACK_IPS` | `10.0.0.1,10.0.0.2,10.0.0.3` | static attacker IP set |
| `SDN_NORMAL_IPS` | `10.0.0.4,10.0.0.5,10.0.0.6` | static normal IP set |
| `SDN_BLOCK_ATTACKS` | `1` | enable hard blocking (not just rerouting) |
| `SDN_BLOCK_THRESHOLD` | `0.5` (= detector's own threshold) | confidence bar to trigger a block |
| `SDN_BLOCK_SECONDS` | `10` | how long a block flow lasts |
| `SDN_SUSPICION_DECAY_SECONDS` | `30.0` | how long a flagged source biases routing cost after it stops attacking |
| `SDN_FLOW_ORIGIN_TTL_SECONDS` | `30.0` | how long the physical-origin cache entry for a flow is trusted |

## New REST endpoints introduced

| Endpoint | Method | Purpose |
|---|---|---|
| `/ids/label_override` | `POST` | set `{"ip", "role": "attack"/"normal", "duration_seconds"}` |
| `/ids/label_override` | `GET` | list currently active overrides |
| `/ids/label_override?ip=...` | `DELETE` | clear an override early |
