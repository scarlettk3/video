# Single Combined Prompt — DQN Mitigation Engine + Detection/Mitigation Multi-Agent Integration

Paste everything below (from "Add the following..." to the end) as one prompt into Claude Code
(or this chat) with `SDN_Security_Framework.ipynb` and `sdn_multiagent_framework.md` attached.

---

```
Add new sections to SDN_Security_Framework.ipynb implementing a DRL/DQN-based SDN Mitigation
Agent that consumes the output of the existing trained Detection Agent (the best ENAS/GAN
ConfigurableMLP model from results["enas_no_gan"] / results["enas_with_gan"]), following the
architecture in sdn_multiagent_framework.md (Section 2.5 Detection Agent, Section 2.6 Mitigation
Agent, Section 2.7 Policy Learning Agent, Section 1.4 Observability Asymmetry, Section 8.3 Phase
1-2 roadmap). Do not modify any existing ENAS/GAN cells or files — only append new cells/sections
and write new files under artifacts/dqn_mitigation/ and the existing artifacts/results/ directory.
Keep train/val/test discipline: train the DQN on val_X/val_y only, and hold test_X/test_y for
final evaluation, exactly as already done for the ENAS/GAN classifier.

--------------------------------------------------------------------------------------------
1. SIMULATED SDN ENVIRONMENT (new section "13. Simulated SDN Environment for Offline DQN
   Training")
--------------------------------------------------------------------------------------------
Build a Gym-style environment class `SDNMitigationEnv` that turns test_X/test_y and val_X/val_y
into an episodic RL environment, without touching Mininet/Ryu — this is the offline pre-training
stage from Section 8.3 Phase 1-2.

- Load the frozen, already-trained Detection Agent (best of BEST_MODEL_GAN_PATH /
  BEST_MODEL_NO_GAN_PATH by test F1/AUROC) wrapped in a `DetectionAgent` class with
  `predict(x_batch) -> (pred_prob, pred_label)` (ConfigurableMLP in eval mode, sigmoid on the
  logit, no gradient updates — it is a frozen feature source only).

- State vector per flow = concatenation of:
  - DetectionAgent's pred_prob (scalar)
  - the flow's existing feature vector from test_X/val_X as-is (already includes pktsSnt,
    pktsRcvd, l7BytesSnt, l7BytesRcvd, duration, pktps, bytps, pktAsm, bytAsm, one-hot l4Proto,
    srcPort_bucket/dstPort_bucket, service-port flags — use feature_columns.json only for
    human-readable logging, never re-derive these; index directly into the processed array)
  - a scalar `congestion_signal` in [0, 1] maintained by the environment itself (see below)

- Congestion is simulated as episode state, not ground truth, per Section 1.4 (defender only sees
  controller-visible telemetry): starts at 0.0 each episode; += 0.05 (clip to 1.0) if a true
  ATTACK flow was "allowed"; *= 0.9 if a true ATTACK flow was mitigated (rate_limit / drop /
  reroute); *= 0.98 for any NORMAL flow regardless of action (natural traffic drain).

- Episode structure: `reset()` samples a shuffled fixed-length window (default 256 flows,
  configurable) from val_X/val_y for training episodes or test_X/test_y for evaluation episodes,
  resets congestion to 0. `step(action)` advances to the next flow, computes reward (see reward
  spec below), and returns (next_state, reward, done, info), where info includes the true label,
  pred_prob, a reward breakdown dict, and running false-positive/false-negative counts for the
  episode.

- Fixed action space, use this exact index order everywhere downstream:
  0 = allow, 1 = monitor, 2 = rate_limit, 3 = install_blocking_rule (drop), 4 = reroute.

- Reward function `_compute_reward(action, true_label, pred_prob)`, exactly as specified (no
  extra terms, for auditability against Section 9.2's ablation table):
  - blocks a real attack (action in {rate_limit, install_blocking_rule, reroute} AND
    true_label == ATTACK): +2.0, or +3.0 specifically for install_blocking_rule
  - allows normal traffic (action == allow AND true_label == NORMAL): +1.0
  - blocks/limits normal traffic — collateral damage (action in {rate_limit,
    install_blocking_rule, reroute} AND true_label == NORMAL): -2.0, extra -1.0 if
    install_blocking_rule
  - allows a real attack through (action == allow AND true_label == ATTACK): -3.0
  - action == monitor: +0.1 if true_label == ATTACK, -0.1 if true_label == NORMAL
  - mitigation cost, subtracted for every action except allow/monitor:
    cost = {rate_limit: 0.2, install_blocking_rule: 0.4, reroute: 0.5}
  - thrash penalty: extra -0.5 if this is the 3rd+ consecutive step (track last 3 actions in a
    deque) where the agent mitigated without congestion actually decreasing
  - return the scalar reward plus a dict breakdown (base_reward, cost_penalty, thrash_penalty) in
    info, for later plotting against Section 9.1's MTTM / % legitimate throughput preserved /
    false-mitigation rate / thrash rate metrics.

Add a short markdown cell noting this env is the offline surrogate from Section 10.1 "Compute
cost", and that a Mininet/Ryu-backed version should replace the synthetic congestion
increment/decay with real OFPPortStatsReply-derived utilization before deployment.

--------------------------------------------------------------------------------------------
2. DQN MITIGATION AGENT + OFFLINE TRAINING LOOP (new section "14. DQN Mitigation Agent
   (offline pre-training)")
--------------------------------------------------------------------------------------------
- `QNetwork(nn.Module)`: MLP, input_dim = SDNMitigationEnv state dim, hidden = [128, 64], ReLU,
  output = 5 Q-values (one per action). Deliberately simpler than ConfigurableMLP since this is a
  control policy, not the perception model.

- `ReplayBuffer`: fixed-capacity deque of (state, action, reward, next_state, done), uniform
  random sampling (note in a comment that prioritized replay is a natural future extension).

- `DQNAgent`: policy_net + target_net (same architecture), hard target sync every
  `target_update_freq=500` steps; epsilon-greedy action selection, epsilon annealed linearly from
  1.0 to 0.05 over the first ~60% of total training steps then held at 0.05; `train_step()`
  samples a batch, computes standard DQN TD target
  (r + gamma * max_a' Q_target(s', a') * (1 - done)), Huber loss against Q_policy(s, a), backprop
  with grad clipping (clip_grad_norm_ to 10.0); gamma = 0.95; Adam, lr = 1e-3.

- Offline training loop: instantiate `SDNMitigationEnv` in "train" mode drawing episodes from
  val_X/val_y; expose `DQN_N_EPISODES = 500` and window length 256 as config constants next to
  the other hyperparameter blocks in the Configuration section; log per-episode total reward,
  mean congestion, false-mitigation rate, missed-attack rate from the info dict; save
  policy_net weights to `DQN_MITIGATION_MODEL_PATH =
  os.path.join(ARTIFACTS_DIR, "dqn_mitigation", "mitigation_policy.pt")` (create the directory)
  and per-episode metrics to `dqn_training_history.json` under RESULTS_DIR, next to
  comparison_results.json. Print a final training summary (20-episode moving average reward,
  false-mitigation rate, missed-attack rate).

--------------------------------------------------------------------------------------------
3. MULTI-AGENT INTEGRATION: DETECTION AGENT -> MITIGATION AGENT (new section "15. Multi-Agent
   Inference Pipeline: Detection Agent -> Mitigation Agent")
--------------------------------------------------------------------------------------------
Build a `DefenderPipeline` class implementing the defender-stack half of
sdn_multiagent_framework.md Section 4 (steps 10-14), using only the already-trained artifacts (no
retraining here):

- `self.detector` = the frozen DetectionAgent from part 1.
- `self.mitigator` = the trained DQNAgent's policy_net loaded from DQN_MITIGATION_MODEL_PATH, eval
  mode, argmax over Q-values only (no exploration).
- `PolicyLearningStub`: a minimal stand-in for Section 2.7's Policy Learning Agent — tracks a
  rolling window of the last 200 decisions' false-positive/false-negative outcomes and exposes
  `current_anomaly_threshold` (starts at 0.5), nudged up by 0.02 if rolling false-mitigation rate
  > 15%, down by 0.02 if rolling missed-attack rate > 5%, clipped to [0.2, 0.8]. Note in a comment
  that this is a bandit-style stand-in for the full meta-RL/Bayesian-optimization agent in
  Section 2.7 (a real implementation would use Ax/BoTorch per Section 8.1).
- `pipeline.process(flow_x)`:
  a. pred_prob, pred_label = self.detector.predict(flow_x)
  b. if pred_prob < policy_stub.current_anomaly_threshold: action = "allow", logged with reason
     "below anomaly threshold" (no mitigation step run)
  c. else: build the Mitigation Agent's state exactly as in part 1 (pred_prob + flow features +
     current congestion from an SDNMitigationEnv instance in "live-sim" mode), let self.mitigator
     pick argmax Q-value action
  d. update policy_stub's rolling stats using the true label (flag clearly in a comment that in
     real deployment this feedback is delayed/analyst-provided, not instantaneous — it's only
     available here because this is still the offline test set)
- Run `pipeline.process` over the full test_X/test_y set (held-out, consistent with how
  test_metrics were computed for the classifier). Produce a results dict: overall accuracy of the
  combined pipeline's final action (allow vs. any-mitigation) against true labels, mean episode
  reward equivalent, false-mitigation rate, missed-attack rate, and action distribution (%
  allow/monitor/rate_limit/drop/reroute). Save as
  `artifacts/results/defender_pipeline_results.json` in a METRIC_ORDER-compatible format so it can
  be added as a third row/column ("Detector + DQN Mitigation Agent") next to the existing
  comparison table.

--------------------------------------------------------------------------------------------
4. EVALUATION, PLOTS, COMPARISON TABLE (extend "12. Inspect Results" or add new section "16.
   Mitigation Evaluation")
--------------------------------------------------------------------------------------------
- Load dqn_training_history.json and plot: (a) episode reward moving average, (b)
  false-mitigation rate and missed-attack rate over episodes on a twin axis, (c) mean congestion
  per episode — reuse SAVE_DPI and EXTENDED_RESULTS_DIR from the existing plotting cell.
- Load defender_pipeline_results.json and produce a bar chart comparing a static-threshold
  baseline (pred_prob > 0.5 -> block, else allow, computed directly from the classifier's existing
  test_metrics) against the full Detection+DQN-Mitigation pipeline, on: false-mitigation rate,
  missed-attack rate, and mean reward-per-flow — the concrete instantiation of Section 9.2's
  baseline (a) "static rule-based SDN defenses" vs. your learned mitigation policy.
- Print a markdown-formatted summary table: rows = {Static threshold, DQN Mitigation Agent},
  columns = {Missed-attack rate, False-mitigation rate, Mean cost per flow, Thrash rate}.
```
