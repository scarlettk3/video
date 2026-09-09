# LFA Defense System — Architecture & Implementation Plan
### ENAS-Searched SD-CGAN (Detection) + Entropy-Weighted Shortest-Path Rerouting (Mitigation)

---

## 1. System Overview

```
                        ┌─────────────────────────────────────────┐
                        │              RYU CONTROLLER              │
                        │                                            │
   Data Plane (Mininet) │  ┌──────────────┐   ┌──────────────────┐ │
   ┌─────────────┐      │  │  Monitor App │──▶│ Feature Extractor │ │
   │  Switches/  │◀────▶│  │ (stats poll) │   │ (entropy, tuples) │ │
   │   Hosts     │ OF   │  └──────────────┘   └─────────┬────────┘ │
   └─────────────┘      │                                │          │
                        │                     ┌──────────▼────────┐ │
                        │                     │  Detector Module   │ │
                        │                     │ (loads SD-CGAN     │ │
                        │                     │  discriminator +   │ │
                        │                     │  scaler from .pkl) │ │
                        │                     └──────────┬────────┘ │
                        │                                │ LFA? Y/N │
                        │                     ┌──────────▼────────┐ │
                        │                     │  Mitigator Module  │ │
                        │                     │ (entropy → link    │ │
                        │                     │  cost → Dijkstra   │ │
                        │                     │  → flow-mod)       │ │
                        │                     └─────────────────────┘ │
                        └─────────────────────────────────────────┘

   OFFLINE (not on the controller, run separately):
   ┌────────────────────────────────────────────────────────┐
   │  ENAS Search Loop → best generator/discriminator cell   │
   │  → Train SD-CGAN on collected traffic → export:         │
   │     - discriminator.pt  (PyTorch weights)                │
   │     - scaler.pkl         (sklearn StandardScaler)         │
   │     - best_arch.json     (ENAS-found architecture)        │
   │     - threshold.pkl      (decision threshold)             │
   └────────────────────────────────────────────────────────┘
```

**Key idea:** ENAS search and SD-CGAN training happen **offline** (you don't run architecture search live on the controller — too slow). The controller only loads the *final trained discriminator* at runtime for fast inference. Mitigation is pure math (entropy + Dijkstra) — no model needed there at all, which is why it's the "easy" half of your proposal.

---

## 2. Module Breakdown

| Module | Runs where | Purpose |
|---|---|---|
| `topology_discovery.py` | Ryu (online) | Builds a live graph of switches/links using LLDP |
| `monitor.py` | Ryu (online) | Polls `OFPFlowStatsRequest` / `OFPPortStatsRequest` periodically |
| `feature_extractor.py` | Ryu (online) | Computes the 7-tuple flow features + per-link entropy |
| `enas_search.py` | Offline (your laptop/GPU) | Runs ENAS to find best generator/discriminator cells |
| `sd_cgan_train.py` | Offline | Trains SD-CGAN using the ENAS-found architecture, exports `.pkl`/`.pt` files |
| `detector.py` | Ryu (online) | Loads exported model, runs inference, flags LFA |
| `mitigator.py` | Ryu (online) | Computes entropy-based link cost, re-runs Dijkstra, installs new flow rules |
| `main_controller.py` | Ryu (online) | Wires all apps together as a Ryu application |

---

## 3. Detection: ENAS + SD-CGAN (Offline Pipeline)

### 3.1 Search space for ENAS
Define a small, fixed set of candidate operations per "cell" (keep it simple — a huge search space will blow your compute budget):

```
OPERATIONS = ["gru_64", "gru_128", "conv1d_k3", "conv1d_k5",
              "fc_relu", "fc_leakyrelu", "identity"]
```

- **Generator search space:** sequence of 2–4 cells, each choosing one op from `OPERATIONS`, operating on the latent noise vector conditioned on the attack-label embedding.
- **Discriminator search space:** same op list, terminating in a sigmoid (real/fake) output, applied to the flow-feature vector (your 7-tuple + entropy features).

### 3.2 ENAS controller
- A small RNN controller (single-layer LSTM, ~50 hidden units is enough) samples an architecture (a sequence of op choices) for the generator and discriminator.
- Train with policy gradient (REINFORCE), reward = **validation F1-score** of the resulting SD-CGAN discriminator on a held-out LFA/normal traffic split.
- Use **weight sharing**: all sampled child architectures share one big parameter pool (this is what makes ENAS "efficient" vs. plain NAS — don't skip this or your search becomes NAS, not ENAS).

*Practical shortcut:* if you're short on time, use an existing NAS library instead of implementing the ENAS controller from scratch:
```bash
pip install nni          # Microsoft's Neural Network Intelligence — has ENAS built in
```
NNI's `enas` trainer lets you plug in your own search space and reward function without writing the RL controller yourself.

### 3.3 SD-CGAN objective (Sinkhorn Conditional GAN)
Replace the paper's plain adversarial loss with:

```
L_D = E[log D(x, y)] + E[log(1 - D(G(z, y), y))]      # conditional discriminator loss
L_G = SinkhornDivergence(P_real(x|y), P_fake(G(z,y)|y))  # generator uses Sinkhorn loss instead of plain minimax
```
Where `y` = attack-type label (normal / LFA), `z` = noise vector, `x` = real feature vector.

Use the **geomloss** library for a ready-made Sinkhorn divergence implementation:
```bash
pip install geomloss
```
```python
from geomloss import SamplesLoss
sinkhorn_loss = SamplesLoss("sinkhorn", p=2, blur=0.05)
loss = sinkhorn_loss(real_batch, fake_batch)
```

### 3.4 Feature vector (matches the paper's septuple + entropy)
```python
features = [
    entropy_srcIP, entropy_dstIP, entropy_proto,   # Shannon/Rényi entropy of qualitative fields
    total_bytes, total_packets,                     # summed quantitative fields
    avg_queue_len, avg_hop_latency                  # from switch/port stats (INT-style if available)
]
```

### 3.5 Offline training script skeleton (`sd_cgan_train.py`)
```python
import torch, pickle, json
from sklearn.preprocessing import StandardScaler

# 1. Load collected flow/switch stats CSV (from your Mininet+Ryu monitor logs)
X, y = load_dataset("traffic_log.csv")

# 2. Scale features
scaler = StandardScaler().fit(X)
X_scaled = scaler.transform(X)

# 3. Build generator/discriminator using the ENAS best_arch.json
with open("best_arch.json") as f:
    arch = json.load(f)
generator = build_model_from_arch(arch["generator"])
discriminator = build_model_from_arch(arch["discriminator"])

# 4. Train with Sinkhorn-based adversarial loop (see 3.3)
train_sd_cgan(generator, discriminator, X_scaled, y, epochs=400)

# 5. Pick decision threshold on validation set (e.g. best F1)
threshold = tune_threshold(discriminator, X_val, y_val)

# 6. Export everything the Ryu controller needs
torch.save(discriminator.state_dict(), "discriminator.pt")
with open("scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)
with open("threshold.pkl", "wb") as f:
    pickle.dump(threshold, f)
```

**Files you hand to Ryu:**
- `discriminator.pt` — trained weights (PyTorch state dict; `.pt` not `.pkl` because PyTorch tensors pickle poorly across versions — safer to use `torch.save`/`torch.load`)
- `scaler.pkl` — the fitted `StandardScaler` (pickle is fine for sklearn objects)
- `threshold.pkl` — the chosen decision threshold (a single float, pickled for consistency)
- `best_arch.json` — architecture definition, needed to *rebuild* the discriminator's structure before loading weights

---

## 4. Detection: Runtime Integration (`detector.py`, inside Ryu)

```python
import torch, pickle, json

class LFADetector:
    def __init__(self):
        with open("best_arch.json") as f:
            arch = json.load(f)
        self.model = build_model_from_arch(arch["discriminator"])
        self.model.load_state_dict(torch.load("discriminator.pt"))
        self.model.eval()

        with open("scaler.pkl", "rb") as f:
            self.scaler = pickle.load(f)
        with open("threshold.pkl", "rb") as f:
            self.threshold = pickle.load(f)

    def predict(self, feature_vector):
        x = self.scaler.transform([feature_vector])
        x = torch.tensor(x, dtype=torch.float32)
        with torch.no_grad():
            score = self.model(x).item()
        return score > self.threshold   # True = LFA detected
```

This module is called every monitoring interval (e.g. every 2–5 seconds) inside your Ryu app's periodic thread.

---

## 5. Mitigation: Entropy-Weighted Shortest-Path Rerouting (`mitigator.py`)

No training, no `.pkl` files needed here — it's pure computation on the live topology graph.

```python
import networkx as nx
import numpy as np

def shannon_entropy(counts):
    probs = counts / counts.sum()
    return -np.sum(probs * np.log2(probs + 1e-12))

def update_link_costs(graph, link_stats, base_cost=1.0, alpha=5.0):
    """
    link_stats: dict {(u,v): recent_packet_size_or_srcIP_distribution}
    Lower entropy (more repetitive/bursty traffic) => higher suspicion => higher cost
    """
    for (u, v), dist in link_stats.items():
        H = shannon_entropy(np.array(dist))
        H_norm = H / np.log2(len(dist))          # normalize to [0,1]
        congestion_factor = 1 - H_norm            # low entropy -> high factor
        cost = base_cost * (1 + alpha * congestion_factor)
        graph[u][v]['weight'] = cost
        graph[v][u]['weight'] = cost
    return graph

def recompute_path(graph, src, dst):
    return nx.dijkstra_path(graph, src, dst, weight='weight')
```

On each detection cycle where `LFADetector.predict()` returns `True`:
1. Recompute per-link entropy from recent flow stats.
2. Update `graph` edge weights with `update_link_costs()`.
3. Recompute shortest paths for affected src-dst pairs with `recompute_path()`.
4. Translate the new path into OpenFlow `flow_mod` messages (standard Ryu `ofproto` + `parser.OFPFlowMod` calls) and push them to the switches along the new path.
5. If entropy returns to normal on the next cycle, costs decay back toward `base_cost`, and routing naturally reverts.

---

## 6. Suggested Project Folder Structure

```
lfa_defense/
├── offline/
│   ├── enas_search.py
│   ├── sd_cgan_train.py
│   ├── best_arch.json          <- output of ENAS
│   ├── discriminator.pt        <- output of SD-CGAN training
│   ├── scaler.pkl
│   └── threshold.pkl
├── ryu_app/
│   ├── main_controller.py
│   ├── topology_discovery.py
│   ├── monitor.py
│   ├── feature_extractor.py
│   ├── detector.py              <- loads offline/ files
│   └── mitigator.py
├── mininet/
│   └── topo.py                  <- Network1/Network2-style topology
└── requirements.txt
```

`requirements.txt`:
```
ryu
mininet          # installed separately, not via pip typically
torch
scikit-learn
geomloss
networkx
numpy
pandas
nni               # optional, if using NNI's built-in ENAS trainer
```

---

## 7. Suggested Evaluation Plan (to compare against the original paper)

| Metric | GLD (paper) | Your ENAS+SD-CGAN | DLM/DDQN (paper) | Your entropy-weighted rerouting |
|---|---|---|---|---|
| Accuracy / Recall / F1 | ✓ | ✓ | — | — |
| Training/search time | — | ✓ (report ENAS search cost) | — | — |
| Network delay | — | — | ✓ | ✓ |
| Packet loss rate | — | — | ✓ | ✓ |
| CPU/memory consumption | — | — | ✓ | ✓ (should be much lower — no RL training) |
| Convergence/reaction time | — | — | ✓ | ✓ (should be near-instant — no training loop) |

This table format matches the original paper's own comparisons (their Figs. 9–15), so your results slot directly next to theirs.

---

## 8. Notes / Things to Decide Before You Start Coding

1. **Rényi vs. Shannon entropy** for the mitigation cost function — Rényi has a tunable sensitivity parameter (α) and is generally better at catching stealthy low-rate floods; Shannon is simpler to implement first, upgrade later if needed.
2. **α (alpha) in the cost formula** controls how aggressively congested links get penalized — tune this experimentally, it's your one main "knob."
3. **Decide your dataset source**: either generate traffic yourself in Mininet (like the original paper, using Iperf for normal + LFA traffic) or use a public dataset (e.g. CICDDoS2019) for pretraining the SD-CGAN before fine-tuning on your own Mininet-collected traffic.
4. **PyTorch vs. TensorFlow**: examples above use PyTorch since `geomloss` (Sinkhorn) integrates natively; switch if your lab's environment already standardizes on TensorFlow.
