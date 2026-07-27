# Single Combined Prompt — LFA Traffic Generation Agent → ENAS+GAN Detection Agent → DQN Mitigation Agent

Paste everything inside the code block below as one prompt into Claude Code (or this chat), with
`SDN_Security_Framework.ipynb` and `sdn_multiagent_framework.md` attached. This targets exactly
three agents from the framework doc — Section 2.4 Traffic Generation Agent (here specialized to
Link-Flooding Attack traffic), Section 2.5 Detection Agent (your existing ENAS+GAN classifier,
reused as-is, frozen), and Section 2.6 Mitigation Agent (new DQN) — wired into one loop.

---

```
Add new sections to SDN_Security_Framework.ipynb implementing a 3-agent offline pipeline: a
Link-Flooding-Attack (LFA) Traffic Generation Agent, the existing trained ENAS+GAN Detection
Agent, and a new DQN Mitigation Agent — following sdn_multiagent_framework.md Section 2.4
(Traffic Generation Agent), Section 2.5 (Detection Agent), Section 2.6 (Mitigation Agent), and
Section 4's step ordering (generate -> detect -> mitigate). Do not modify any existing ENAS/GAN
training cells, best_model_no_gan.pt, best_model_gan.pt, or comparison_results.json — only append
new cells/sections and write new files under artifacts/lfa_agent/, artifacts/dqn_mitigation/, and
artifacts/results/. Keep train/val/test discipline throughout: any new synthetic traffic is
generated from and evaluated against val_X/val_y and test_X/test_y only, never used to retrain
the already-trained ENAS+GAN classifier.

--------------------------------------------------------------------------------------------
AGENT 1 — LFA Traffic Generation Agent (new section "13. LFA Traffic Generation Agent")
--------------------------------------------------------------------------------------------
Per Section 2.4, this agent is a generative model (reuse the existing tabular GAN
Generator/Discriminator classes and GAN_GENERATOR_PATH already trained on real ATTACK rows in
this notebook) with an RL-controlled adversarial "mode", not a from-scratch RL policy emitting
raw packets.

1. `LFAProfile`: define what makes a flow LFA-like in this dataset's feature space (justify each
   choice in a comment referencing the real LFA mechanism — many low-and-slow flows converging on
   a shared bottleneck link/target so no single flow looks like an obvious flood):
   - high pktps/bytps relative to duration but NOT extreme single-flow volume (LFA flows mimic
     legitimate traffic individually — this is what makes them hard to detect vs. a naive flood)
   - low pktAsm/bytAsm variance across the batch (many flows behaving near-identically is the
     LFA "crowding" signature)
   - duration clustered in a narrow band (coordinated, near-simultaneous flows)
   - concentrated toward whichever port bucket / protocol combination already correlates most
     with the ATTACK class in feature_columns.json / the trained classifier's learned weights (log
     which one you picked and why)
   Encode LFAProfile as a target statistics dict (means/stds per feature) computed from the real
   ATTACK subset of val_X that best matches the above criteria (i.e., a sub-cluster of real attack
   rows, not invented values) — this keeps generation grounded in the actual dataset distribution
   instead of hand-waved numbers.

2. `LFAGenerator` class wrapping the existing trained `Generator` (load GAN_GENERATOR_PATH):
   - `generate_batch(batch_size, evasion_strength)` samples noise, runs it through the frozen
     pretrained Generator to get a batch of attack-like flow vectors, then nudges each sample
     toward LFAProfile's target statistics with a weighted blend
     `x_lfa = (1 - evasion_strength) * x_gan_raw + evasion_strength * project_to_lfa_profile(x_gan_raw)`
     where `project_to_lfa_profile` clips/shifts only the features named in LFAProfile toward
     their target mean, leaving all other features untouched. This keeps every generated sample
     inside the real feature manifold the Generator already learned, rather than fabricating an
     out-of-distribution vector.
   - Do NOT unfreeze or fine-tune the underlying Generator weights here — only compose its output
     downstream. Note in a comment that a full retraining of a conditional/LFA-specific GAN is a
     valid future extension but out of scope for this offline pass.

3. `EvasionModeController` — the "RL only for adversarial mode-control" piece from Section 2.4:
   a small bandit/contextual-bandit (epsilon-greedy over a discrete set of `evasion_strength`
   values, e.g. {0.0, 0.25, 0.5, 0.75, 1.0}) that, each generation round, picks an evasion_strength,
   generates a batch, scores it with the frozen Detection Agent (Agent 2 below), and updates its
   value estimate for that arm using
   `reward = 1 - detection_agent.predict(batch).mean_pred_prob` (i.e., reward is high when the
   Detection Agent is LESS confident these are attacks — the adversarial reward described in
   Section 2.4, "attack objective achieved minus a distinguishability penalty from the Detection
   Agent's confidence score"). Log the learned per-arm value estimates so you can show, in the
   evaluation section, which evasion_strength the LFA agent converges to.

Save `lfa_generation_log.json` under artifacts/lfa_agent/ with, per round: evasion_strength
chosen, mean/std of the Detection Agent's pred_prob on that batch, and the arm value estimates.

--------------------------------------------------------------------------------------------
AGENT 2 — Detection Agent (reuse existing ENAS+GAN classifier, no changes — new section "14.
Detection Agent: Evaluating LFA Traffic")
--------------------------------------------------------------------------------------------
- Wrap the already-trained best classifier (whichever of results["enas_with_gan"] /
  results["enas_no_gan"] has better test F1/AUROC — prefer enas_with_gan if present, since it was
  specifically trained to be robust to GAN-style synthetic attacks, which is the realistic
  detector for this scenario) in a frozen `DetectionAgent` class:
  `predict(x_batch) -> (pred_prob, pred_label)` using ConfigurableMLP.eval() + sigmoid, no
  gradient updates, exactly matching how predict_proba is already used elsewhere in the notebook.
- Run the Detection Agent against three populations for a clean before/after comparison, all
  reported in one table: (a) real NORMAL flows from test_X/test_y, (b) real ATTACK flows from
  test_X/test_y, (c) synthetic LFA batches from Agent 1 at each evasion_strength arm. Metrics per
  population: mean pred_prob, detection rate at threshold 0.5, precision/recall/F1 where ground
  truth is available (real populations only — synthetic LFA batches are all-positive by
  construction, so only report detection rate = mean pred_label there).
- Save as `artifacts/results/lfa_detection_results.json`.

--------------------------------------------------------------------------------------------
AGENT 3 — DQN Mitigation Agent (new sections "15. Simulated SDN Environment" and "16. DQN
Mitigation Agent")
--------------------------------------------------------------------------------------------
Build `SDNMitigationEnv`, a Gym-style offline environment whose episodes are now explicitly
LFA-centric: each episode's flow stream is a shuffled MIX of real NORMAL flows, real ATTACK flows,
and Agent 1's synthetic LFA batches (mix ratio configurable, default 60% normal / 20% real attack
/ 20% synthetic LFA, drawn from val_X/val_y for training episodes and test_X/test_y + fresh LFA
batches for evaluation episodes) — this is what makes the environment a genuine LFA-mitigation
simulator per Section 8.3 Phase 1-2, rather than a generic attack-mitigation environment.

State per flow = concatenation of:
- Detection Agent's pred_prob for this flow
- the flow's existing feature vector as-is from val_X/test_X (pktsSnt, pktsRcvd, l7BytesSnt,
  l7BytesRcvd, duration, pktps, bytps, pktAsm, bytAsm, one-hot l4Proto, srcPort_bucket/
  dstPort_bucket, service-port flags — index directly, never re-derive)
- `congestion_signal` in [0, 1], maintained by the environment: this must specifically model
  LINK congestion (the actual LFA objective per Section 2.3's static features like edge-
  betweenness), not generic switch load: increment congestion faster and by a larger step when
  multiple consecutive "allowed" flows in the same episode window are synthetic-LFA-sourced or
  real-ATTACK (e.g. += 0.08 per such flow, clipped to 1.0, reflecting how LFA's many-flow
  crowding compounds); decay congestion when such flows are mitigated (rate_limit / drop /
  reroute: *= 0.85) or when a flow is real NORMAL (*= 0.98, natural drain).

Action space (fixed index order): 0 = allow, 1 = monitor, 2 = rate_limit,
3 = install_blocking_rule (drop), 4 = reroute.

Reward `_compute_reward(action, true_label, pred_prob, is_synthetic_lfa)`:
- blocks a real attack or a synthetic LFA flow (action in {rate_limit, install_blocking_rule,
  reroute} AND (true_label == ATTACK OR is_synthetic_lfa)): +2.0, +3.0 specifically for
  install_blocking_rule
- allows normal traffic (action == allow AND true_label == NORMAL AND not is_synthetic_lfa): +1.0
- blocks/limits normal traffic — collateral damage: -2.0, extra -1.0 if install_blocking_rule
- allows a real attack or synthetic LFA flow through (action == allow AND
  (true_label == ATTACK OR is_synthetic_lfa)): -3.0
- action == monitor: +0.1 if (true_label == ATTACK OR is_synthetic_lfa), -0.1 if NORMAL
- mitigation cost, subtracted for every action except allow/monitor:
  cost = {rate_limit: 0.2, install_blocking_rule: 0.4, reroute: 0.5}
- thrash penalty: extra -0.5 if this is the 3rd+ consecutive mitigating step without congestion
  actually decreasing (track last 3 actions in a deque)
Return the scalar reward plus a breakdown dict (base_reward, cost_penalty, thrash_penalty) in info.

DQN implementation:
- `QNetwork`: MLP, input_dim = env state dim, hidden = [128, 64], ReLU, output = 5 Q-values.
- `ReplayBuffer`: fixed-capacity deque, uniform random sampling.
- `DQNAgent`: policy_net + target_net (hard sync every 500 steps), epsilon-greedy annealed 1.0 ->
  0.05 over ~60% of training steps, Huber loss on TD target
  (r + gamma * max_a' Q_target(s', a') * (1 - done)), grad clipping to 10.0, gamma = 0.95, Adam
  lr = 1e-3.
- Offline training loop over `DQN_N_EPISODES = 500` episodes of window length 256 (config
  constants next to the notebook's existing hyperparameter block), episodes drawn from val_X/
  val_y + freshly generated LFA batches (call Agent 1's generator inside the training loop with a
  fixed evasion_strength schedule matching what EvasionModeController converged to, or vary it
  across episodes for robustness — pick one and justify in a comment). Log per-episode reward,
  mean congestion, false-mitigation rate, missed-attack rate (missed = allow on ATTACK or LFA).
  Save policy_net to `artifacts/dqn_mitigation/mitigation_policy.pt` and per-episode metrics to
  `dqn_training_history.json` under artifacts/results/.

--------------------------------------------------------------------------------------------
FULL LOOP — Traffic Generation Agent -> Detection Agent -> Mitigation Agent (new section "17.
Full Multi-Agent Loop")
--------------------------------------------------------------------------------------------
Build a `DefenderPipeline` (Detection Agent + trained DQN Mitigation policy, argmax/no
exploration, exactly as in Agent 2/3 above) and an `AttackerLoop` that repeatedly: (1) Agent 1
generates an LFA batch at its converged evasion_strength, (2) DefenderPipeline.process runs each
generated flow (and, interleaved, real test_X/test_y flows at the mix ratio above) through
Detection Agent then Mitigation Agent, (3) the environment's congestion_signal is updated and fed
back as the next step's state, closing the loop end-to-end over the full held-out test_X/test_y
plus fresh LFA batches (test set only — no val leakage at this final evaluation stage). Produce
and save `artifacts/results/full_lfa_pipeline_results.json` with: LFA detection rate before vs.
after the Mitigation Agent acts, missed-attack rate, false-mitigation rate, mean congestion
trajectory, and action distribution (% allow/monitor/rate_limit/drop/reroute) broken out
separately for the real-ATTACK, real-NORMAL, and synthetic-LFA sub-populations.

--------------------------------------------------------------------------------------------
EVALUATION (new section "18. Evaluation: LFA Generation, Detection, and Mitigation")
--------------------------------------------------------------------------------------------
1. Plot the EvasionModeController's per-arm value estimates over rounds (does the LFA agent
   converge to a specific evasion_strength that most degrades detector confidence?).
2. Plot Detection Agent's mean pred_prob on synthetic LFA batches vs. real ATTACK vs. real NORMAL
   (bar chart, one bar per population) — this is the direct evidence of "can ENAS+GAN detect the
   generated LFA traffic."
3. Plot DQN training curves: episode reward moving average, false-mitigation/missed-attack rate,
   mean congestion per episode (reuse SAVE_DPI / EXTENDED_RESULTS_DIR from the existing plotting
   cell).
4. Plot congestion trajectory over the full-loop evaluation window before vs. after the
   Mitigation Agent is enabled (i.e., same LFA batches run once with DQN mitigation active and
   once with a static-threshold-only baseline, action = drop if pred_prob > 0.5 else allow, no
   monitor/rate_limit/reroute) — this is the direct instantiation of Section 9.2's baseline
   comparison (a) static rule-based defense vs. your learned Mitigation Agent, specifically on
   the metric that matters for LFA (does core-link congestion actually go down faster).
5. Print a markdown summary table: rows = {Static threshold, DQN Mitigation Agent}, columns =
   {LFA detection rate, Missed-attack rate, False-mitigation rate, Steps to congestion < 0.2
   (a simple stand-in for MTTM — mean time to mitigate — from Section 9.1)}.
```

---

### How this maps to sdn_multiagent_framework.md

- **Traffic Generation Agent** (Section 2.4): implemented as GAN-reuse + bandit-based adversarial
  evasion-mode control, exactly matching the doc's explicit "RL controls GAN mode" design and its
  stated reward (attack objective − Detection Agent confidence penalty), not raw end-to-end RL
  packet generation.
- **Detection Agent** (Section 2.5): your already-trained ENAS+GAN classifier, reused frozen —
  no retraining, no architecture changes, so results stay comparable to your existing
  comparison_results.json.
- **Mitigation Agent** (Section 2.6): the DQN, with congestion modeled specifically around the
  LFA mechanism (many-flow link crowding) rather than a generic per-flow signal, and reward terms
  matching the doc's cost/thrash language.
- The full-loop section instantiates Section 4's step ordering (generate → detect → mitigate) and
  Section 9.2's baseline-comparison requirement, all still fully offline/dataset-driven — no
  Mininet/Ryu required, consistent with "create a simulated SDN environment using the test
  dataset" from your original request.
