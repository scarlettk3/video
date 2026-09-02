# Complete Beginner-to-Expert Guide to the Project

Project title:

```text
Evolutionary Neural Architecture Search with GAN-Augmented Training for
Link Flooding Attack Detection in Software-Defined Networks
```

## How to Read This Document

This guide is written so that a reader with almost no background can still understand the whole project, and a technical reader can still trust the details. Every important term is explained in plain language first, then in technical language. If you read this document from top to bottom, you will understand:

- What problem the project solves.
- Why each technology is used.
- What happens during training.
- What happens during live detection.
- How attacks are detected and stopped.
- How to explain everything confidently.

A short reading tip:

- Bold plain-language lines explain the idea simply.
- Code blocks show the exact flow, formula, or structure.
- Tables summarize responsibilities and differences.

## Table of Contents

1. The Problem in Simple Words
2. The Core Idea of the Solution
3. Key Terms Explained Simply
4. Complete System Architecture
5. Training Pipeline vs Live Detection Pipeline
6. Every Module Explained
7. Traffic Generation
8. Ryu Controller Monitoring
9. Feature Extraction
10. GAN Augmentation
11. Evolutionary Neural Architecture Search
12. Final Machine Learning Model
13. Real-Time Detection Using Ryu
14. How Ryu Identifies the Attacker
15. Link Utilization Detection
16. Attack Mitigation
17. Complete Detection and Mitigation Flow
18. Ryu Implementation Logic and Pseudocode
19. Architecture Diagrams
20. A Full Numerical Attack Example
21. Interview and Viva Preparation
22. Common Misunderstandings to Avoid
23. Final Summary

## 1. The Problem in Simple Words

**Imagine a city with many roads. Cars are like network traffic. A hospital is like an important server. If attackers block the main road to the hospital with many slow cars, ambulances cannot get through, even though the hospital itself is perfectly fine.**

This is exactly what a Link Flooding Attack (LFA) does in a computer network.

- The attackers do not always attack the server directly.
- Instead, they flood a specific network link that many users depend on.
- Each attacker sends traffic that looks normal on its own.
- Together, they congest one shared link.
- Legitimate users lose access because the road, not the destination, is blocked.

**The goal of this project is to detect this kind of attack automatically and then clear the road so real users can pass again.**

## 2. The Core Idea of the Solution

The solution has two big parts.

**Part 1: Teach a computer to recognize attack traffic.**

This is done offline, before deployment, using machine learning. The system studies many examples of normal and attack traffic and learns to tell them apart.

**Part 2: Watch the live network and act instantly.**

This is done online, during deployment, using Software-Defined Networking. A central controller watches the network, uses the trained model to judge traffic, and then reprograms the network to block or slow down attackers.

Two supporting techniques make the model stronger before deployment:

- **GAN augmentation** creates extra realistic attack examples so the model learns better.
- **ENAS** automatically designs the best neural-network shape instead of a human guessing it.

## 3. Key Terms Explained Simply

| Term | Simple meaning | Technical meaning |
| --- | --- | --- |
| SDN | A network with a smart central brain | Software-Defined Networking separates control logic from forwarding hardware |
| Ryu | The brain program | A Python SDN controller that speaks OpenFlow |
| OpenFlow | The language the brain uses to command switches | A protocol between controller and switches |
| Switch | A traffic junction | A device that forwards packets based on rules |
| Mininet | A virtual practice network | A network emulator that creates virtual hosts and switches |
| Flow | One conversation between two endpoints | Packets sharing the same source, destination, ports, and protocol |
| Feature | A measurable property of traffic | A numeric input value for the model |
| Model | The trained decision-maker | A neural network classifier |
| MLP | A simple layered neural network | Multi-Layer Perceptron |
| GAN | A fake-data generator with a critic | Generative Adversarial Network |
| ENAS | Automatic model designer | Evolutionary Neural Architecture Search |
| LFA | Road-blocking attack | Link Flooding Attack |
| Mitigation | The fix or response | Control actions that stop or reduce attack traffic |

**If you remember only one sentence: SDN gives control, the model gives judgment, and together they detect and stop link-flooding attacks.**

## 4. Complete System Architecture

The whole system, from people to protection, looks like this:

```text
Normal users / attackers
    -> Mininet hosts (virtual computers)
    -> OpenFlow switches (traffic junctions)
    -> Ryu controller (the brain)
    -> flow-statistics or flow-record collection (observation)
    -> feature extraction (turn traffic into numbers)
    -> preprocessing (clean and scale the numbers)
    -> [TRAINING ONLY] GAN augmentation (make more attack samples)
    -> [TRAINING ONLY] ENAS optimization (design best model)
    -> trained intrusion-detection model (the judge)
    -> real-time attack detection (live judgment)
    -> Ryu mitigation module (the responder)
    -> OpenFlow rules installed on switches (the action)
```

**In one breath: traffic is observed, turned into numbers, judged by a trained model, and if it is an attack, the controller reprograms the switches to stop it.**

## 5. Training Pipeline vs Live Detection Pipeline

This is the single most important distinction in the whole project. Many people confuse the two. Keep them separate.

**Training happens once, in advance, in a notebook. Detection happens continuously, live, in the Ryu controller.**

### Offline training pipeline

```text
Raw labelled dataset
    -> cleaning and feature engineering
    -> train / validation / test split
    -> fit preprocessing on training data only
    -> GAN augmentation of attack samples
    -> ENAS search for best architecture
    -> final MLP training
    -> evaluation on test data
    -> save model + preprocessing artifacts
```

### Online detection pipeline

```text
Live network traffic
    -> OpenFlow switches
    -> flow extractor (Tranalyzer2 or CICFlowMeter)
    -> flow records sent to Ryu
    -> load saved preprocessing (do not refit)
    -> saved model predicts attack probability
    -> mitigation decision
    -> OpenFlow rules block / rate-limit / reroute
```

### Side-by-side comparison

| Question | Offline training | Online detection |
| --- | --- | --- |
| When does it run? | Once, before deployment | Continuously, during operation |
| Where does it run? | Notebook / training machine | Inside the Ryu controller |
| Does it need switches? | No | Yes |
| Does it use GAN? | Yes | No, not for each live flow |
| Does it use ENAS? | Yes | No |
| Does it change the model? | Yes, it creates it | No, it only uses it |
| Main output | A saved model + preprocessor | Live decisions and mitigation |

**Say this in a viva: GAN and ENAS are training-time tools. The live controller only loads the finished model and applies it.**

## 6. Every Module Explained

A quick note on wording. In strict software engineering, these are **modules or components**, not autonomous agents. A true agent senses, decides, and acts on its own. A few parts here are agent-like (the mitigation policy decides an action, and the LFA generator produces data), but the technically correct word for the whole system is **modules** or **pipeline stages**.

**Recommended phrasing: "The system is built from modules; a few behave like agents, but they are implemented as software components."**

For each module below: responsibility, input, processing, output, receiver, and when it runs.

### 6.1 Traffic Generation Module

- **Responsibility:** create normal and attack traffic for testing.
- **Input:** network topology, host list, and a traffic plan.
- **Processing:** normal hosts send everyday traffic; attacker hosts send coordinated low-rate flows aimed at one link.
- **Output:** packets in the network plus a ground-truth log of what was normal and what was attack.
- **Receiver:** OpenFlow switches and the flow extractor.
- **Runs during:** testing and evaluation, not core model training.

### 6.2 Data Collection Module

- **Responsibility:** capture traffic and group it into flows.
- **Input:** packets on a monitored/mirrored interface.
- **Processing:** groups packets that belong to the same conversation and counts bytes, packets, and timing.
- **Output:** raw flow records.
- **Receiver:** feature extraction module.
- **Runs during:** dataset creation and live detection.

### 6.3 Feature Extraction Module

- **Responsibility:** turn raw flow records into meaningful numbers.
- **Input:** flow records from Tranalyzer2 or CICFlowMeter.
- **Processing:** computes packet rate, byte rate, duration, packet-size statistics, timing statistics, and direction/asymmetry values.
- **Output:** a raw feature set for one flow.
- **Receiver:** preprocessing module.
- **Runs during:** training and live detection.

### 6.4 Preprocessing Module

- **Responsibility:** make live features look exactly like training features.
- **Input:** raw feature set plus saved preprocessing objects.
- **Processing:** fills missing values, buckets ports, adds service-port flags, applies log transforms, encodes categories, scales numbers, and keeps the exact column order.
- **Output:** a fixed-size numeric vector (currently 122 values).
- **Receiver:** the ML detection module.
- **Runs during:** training (fitted) and live detection (applied only, never refitted).

**Why this matters: if live preprocessing differs even slightly from training, predictions become unreliable. Consistency is critical.**

### 6.5 GAN Augmentation Module

- **Responsibility:** invent realistic extra attack samples.
- **Input:** real attack samples and random noise.
- **Processing:** a generator creates fake attack samples; a discriminator critiques them; both improve until fakes look realistic.
- **Output:** synthetic attack feature vectors.
- **Receiver:** the training dataset.
- **Runs during:** offline training only (optionally for controlled simulation later).

### 6.6 ENAS Optimization Module

- **Responsibility:** automatically design the best neural network.
- **Input:** training/validation data and a search space of architectures.
- **Processing:** builds candidate networks, trains them briefly, scores them, keeps the best, mixes and mutates them, and repeats over generations.
- **Output:** the best architecture configuration.
- **Receiver:** the final training step.
- **Runs during:** offline training only.

### 6.7 ML Detection Module

- **Responsibility:** decide if one flow looks like an attack.
- **Input:** a preprocessed feature vector.
- **Processing:** runs the trained MLP and produces an attack probability.
- **Output:** a probability and a normal/attack label.
- **Receiver:** the attack-detection logic.
- **Runs during:** offline evaluation and live detection.

### 6.8 Ryu Monitoring Module

- **Responsibility:** keep track of switches, ports, and forwarding.
- **Input:** OpenFlow events and optional statistics replies.
- **Processing:** registers switches, learns addresses, installs default forwarding, and can request statistics.
- **Output:** network state and link/port context.
- **Receiver:** detection and mitigation modules.
- **Runs during:** live operation.

### 6.9 Attack Detection Module

- **Responsibility:** turn a probability into a suspicious/normal judgment.
- **Input:** model probability, flow identity, optional link utilization.
- **Processing:** compares the probability to a threshold and can combine it with congestion evidence.
- **Output:** a decision and a recommended action.
- **Receiver:** the mitigation module.
- **Runs during:** live detection.

### 6.10 Mitigation Module

- **Responsibility:** turn a decision into a network action.
- **Input:** the suspicious flow identity and the chosen action.
- **Processing:** builds OpenFlow match fields and sends FlowMod or MeterMod messages.
- **Output:** installed switch rules.
- **Receiver:** OpenFlow switches.
- **Runs during:** live mitigation.

### 6.11 OpenFlow Rule Management Module

- **Responsibility:** install, prioritize, and expire switch rules.
- **Input:** match fields, priority, action, timeout, and meter rate.
- **Processing:** creates high-priority rules and rate-limit meters with timeouts.
- **Output:** changes in switch behavior.
- **Receiver:** the switch data plane.
- **Runs during:** live mitigation.

## 7. Traffic Generation

**Mininet is a virtual lab. It lets you build a whole network of computers and switches inside one machine, so you can safely test attacks.**

Example network:

```text
h1, h2, h3 = legitimate users
h4, h5, h6 = attackers
s1, s2, s3 = OpenFlow switches

        h1        h2
         \        /
          s1 ---- s2 ---- s3 ---- target/server
         /        \
       h4          h3
                  /  \
                h5    h6

Ryu controls s1, s2, and s3.
```

### What normal hosts do

Normal hosts behave like ordinary people using the internet:

- `h1` browses websites.
- `h2` sends DNS lookups and SSH sessions.
- `h3` downloads or uploads files.

Their traffic is varied: many destinations, different ports, different sizes, and different durations.

### What attacker hosts do

Attacker hosts (`h4`, `h5`, `h6`) act like a coordinated team of bots:

- They pick one shared link to overload, for example `s2-s3`.
- They send many flows that all cross that link.
- Each flow is intentionally modest so it does not look obviously malicious.

### How attackers coordinate

**Think of many small streams joining into one flood at a single bridge.** The attackers deliberately choose paths that all pass through the same target link, so their combined traffic overwhelms it.

### How LFA differs from normal DDoS

| Aspect | Traditional DDoS | Link Flooding Attack |
| --- | --- | --- |
| Main target | The server itself | A shared network link |
| Traffic per source | Often very high | Often low and stealthy |
| Appearance | Obvious flood | Looks like normal traffic |
| Effect | Server overloaded | Path/link congested |
| Detection difficulty | Easier | Harder |

**Key sentence: LFA blocks the road, not the building. That is why link utilization and flow convergence matter so much.**

## 8. Ryu Controller Monitoring

**Ryu is the brain. Switches are its hands. OpenFlow is the language between them.**

### Important OpenFlow messages

| Message | Direction | Plain meaning |
| --- | --- | --- |
| `PacketIn` | Switch to Ryu | "I have a packet with no rule. What do I do?" |
| `FlowMod` | Ryu to switch | "Here is a rule. Follow it." |
| `OFPFlowStatsRequest` | Ryu to switch | "Give me your flow counters." |
| `OFPFlowStatsReply` | Switch to Ryu | "Here are my flow counters." |
| `OFPPortStatsRequest` | Ryu to switch | "Give me your port counters." |
| `OFPPortStatsReply` | Switch to Ryu | "Here are my port counters." |
| `MeterMod` | Ryu to switch | "Add this speed limit." |

### Step-by-step monitoring

```text
Ryu -> sends OFPFlowStatsRequest
Switch -> replies with OFPFlowStatsReply
Ryu -> extracts flow information
Ryu -> sends OFPPortStatsRequest
Switch -> replies with OFPPortStatsReply
Ryu -> calculates rates and link utilization
Ryu -> passes features/context to detection logic
```

### What a flow can tell us

From flow information, Ryu can learn:

```text
source IP
destination IP
source port
destination port
protocol
packet count
byte count
flow duration
packet rate (packets per second)
byte rate (bytes per second)
input port
output port
```

TCP flags can also be relevant in some designs to see connection behavior.

**Honesty point for the viva: OpenFlow counters are useful, but the trained model in this project expects richer per-flow features. That is why a flow extractor supplies the model input, while Ryu still handles control and mitigation.**

## 9. Feature Extraction

**Feature extraction is translation. It turns messy raw traffic into clean numbers a model can understand.**

Useful LFA features:

```text
packet rate
byte rate
flow duration
number of flows
source diversity
destination diversity
port utilization
link utilization
packet size
inter-arrival time
```

### Option A: Compute features inside Ryu

Ryu can calculate some values directly from OpenFlow counters:

```text
packet_rate = (packets_now - packets_before) / time_interval
byte_rate   = (bytes_now - bytes_before) / time_interval
flow_duration = duration_seconds + duration_nanoseconds
```

- **Advantage:** everything stays in the controller.
- **Limitation:** hard to get packet-size distributions and precise timing statistics.

### Option B: Use CICFlowMeter or Tranalyzer2

A dedicated flow extractor computes rich features from captured packets.

- **Advantage:** features match the training dataset closely.
- **Limitation:** needs an extra capture pipeline and field-name mapping.

### Recommended architecture

**Use a hybrid design.**

```text
Flow extractor -> rich features -> model prediction
Ryu OpenFlow stats -> link utilization and which port is congested
Ryu OpenFlow rules -> mitigation
```

This keeps the model accurate and still uses SDN visibility to see which link is under stress.

## 10. GAN Augmentation

**A GAN is like a forger and a detective who train each other.** The forger makes fake attack samples; the detective tries to spot fakes. Over time the forger becomes so good that its fakes look real, and those realistic fakes are used to teach the main model.

Why it is needed:

- Real attack samples, especially subtle LFA samples, are often scarce.
- A model trained on few attack examples may miss stealthy attacks.
- Extra realistic attack samples improve balance and robustness.

### Generator

- **Input:** random noise.
- **Output:** a synthetic attack feature vector.

### Discriminator

- **Input:** a real or synthetic sample.
- **Output:** a guess of real vs fake.

### Training loop

```text
1. Take real attack samples.
2. Generator makes fake attack samples from noise.
3. Discriminator learns real vs fake.
4. Generator learns to fool the discriminator.
5. Repeat until fakes are realistic.
6. Add fakes to the training set.
7. Train the detector on the combined data.
```

**Critical clarity point: GAN belongs to offline training. It does not run for every live packet. In this project the saved generator can also drive a controlled LFA simulation for evaluation, but normal detection uses only the finished detector.**

## 11. Evolutionary Neural Architecture Search

**ENAS is like breeding the best model instead of hand-building one.** It treats each candidate network like an individual in a population, keeps the strongest, and evolves better ones.

Each candidate architecture is defined by:

```text
number of hidden layers
number of neurons per layer
activation function (ReLU, LeakyReLU, GELU)
dropout rate
learning rate
batch size
```

### How it works

```text
1. Create an initial population of random architectures.
2. Train each candidate briefly.
3. Score each candidate on validation data (fitness = F1-score).
4. Select the best-performing candidates.
5. Crossover: combine good traits of two parents.
6. Mutation: randomly change some settings.
7. Form the next generation.
8. Repeat for several generations.
9. Choose the best architecture overall.
```

### Worked example

```text
Generation 1:
Architecture A -> F1 = 0.86
Architecture B -> F1 = 0.89
Architecture C -> F1 = 0.84

Selection keeps B and A.
Crossover mixes their settings.
Mutation tweaks a few values.

Generation 2:
Architecture D -> F1 = 0.91
Architecture E -> F1 = 0.92

Best architecture E is chosen for final training.
```

**Why not design it by hand? Manual design is slow and biased. ENAS searches many combinations objectively and picks the one that actually scores best on validation data.**

## 12. Final Machine Learning Model

Once ENAS picks the best architecture, the final model is trained fully.

```text
Dataset
    -> preprocessing
    -> train / test split
    -> optional GAN augmentation
    -> ENAS-selected architecture
    -> final training
    -> evaluation
    -> saved model file (.pt checkpoint)
    -> loaded by the Ryu application
```

### How to interpret 96% accuracy and 0.92 F1

- **Accuracy 96%** means about 96 out of 100 flows were classified correctly on the test set.
- **F1-score 0.92** means the model balances two concerns well:

```text
precision = of the flows flagged as attacks, how many were truly attacks
recall    = of all real attacks, how many were caught
F1        = balanced combination of precision and recall
```

### Why F1 matters more than accuracy for security

**If attacks are rare, a lazy model that says "everything is normal" can still score high accuracy while missing every attack.** F1 exposes this by punishing both missed attacks and false alarms. For intrusion detection:

- Low recall = dangerous, real attacks slip through.
- Low precision = annoying and harmful, real users get blocked.
- High F1 = a healthy balance.

## 13. Real-Time Detection Using Ryu

This is the heart of the live system. Follow the steps carefully.

```text
Step 1: Ryu starts and loads the saved preprocessing and trained model.
Step 2: OpenFlow switches connect to Ryu.
Step 3: Ryu installs default forwarding rules so normal traffic flows.
Step 4: Hosts send traffic; the flow extractor turns it into flow records.
Step 5: Each flow record is sent to Ryu.
Step 6: Ryu applies the same preprocessing used in training.
Step 7: Ryu runs the model and gets an attack probability.
Step 8: If probability crosses the threshold, the flow is suspicious.
Step 9: Ryu identifies the flow's source, destination, ports, and switch.
Step 10: Ryu installs a mitigation rule on the switch.
```

Example probabilities:

```text
Normal flow -> P(attack) = 0.08
Attack flow -> P(attack) = 0.92
```

Default decision rule:

```text
P(attack) > 0.5  -> treat as attack
P(attack) <= 0.5 -> treat as normal
```

**In plain words: Ryu watches, the model judges, and Ryu acts. The model never touches the switches directly; Ryu does.**

## 14. How Ryu Identifies the Attacker

**A common confusion: the model only says "this looks malicious." It does not name the attacker. Ryu names the attacker using the flow's identity.**

Every flow record carries identity fields:

```text
source IP
destination IP
source port
destination port
protocol
switch datapath ID (dpid)
input / output port (when available)
timestamp
```

So when the model flags a flow such as:

```text
srcIP = 10.0.0.5
dstIP = 10.0.0.10
srcPort = 50120
dstPort = 80
protocol = TCP
dpid = 1
```

Ryu can install a rule on switch `dpid = 1` that matches exactly this traffic.

### Finding the congested link

Ryu determines the affected link by combining:

- The switch datapath ID.
- The input and output ports.
- Topology knowledge (which port connects to which link).
- Port statistics (which port is overloaded).

**If many suspicious flows all exit through the same switch port, and that port is saturated, that link is the flooded target.**

## 15. Link Utilization Detection

**Link utilization answers: how full is this road right now?**

Formula:

```text
Utilization = (current_tx_bytes - previous_tx_bytes) * 8
              / (time_interval_seconds * link_bandwidth_bits_per_second)
```

Worked example:

```text
previous_tx_bytes = 100,000,000
current_tx_bytes  = 111,500,000
delta_bytes       = 11,500,000
time_interval     = 1 second
link_bandwidth    = 100 Mbps

Utilization = 11,500,000 * 8 / (1 * 100,000,000)
Utilization = 92,000,000 / 100,000,000
Utilization = 0.92 = 92%
```

### Combining ML with link utilization

A strong LFA decision uses multiple signals together:

```text
link utilization > 80%
+ model predicts attack
+ many suspicious flows share the same link
=> Link Flooding Attack confirmed
```

**Does this reduce false positives? Yes.** A single suspicious flow on an empty link is low risk. A suspicious flow on a saturated shared link is strong evidence. Requiring both conditions avoids overreacting to harmless traffic.

## 16. Attack Mitigation

**Mitigation is the response. Ryu does not delete packets itself; it tells switches what to do.**

### A. Drop the flow

```text
match: attacker IP + target IP + protocol/port
action: DROP
```

- **Effect:** malicious traffic is discarded at the switch.
- **Pro:** immediate and strong.
- **Con:** dangerous if the prediction is wrong; can block real users sharing that address.

### B. Rate limiting

Ryu installs an OpenFlow meter that caps bandwidth.

```text
match: suspicious flow
action: apply meter (speed limit), then forward
```

- **Pro:** safer; traffic is slowed, not killed.
- **Con:** some attack traffic still passes.

### C. Rerouting

Ryu moves traffic to a different path or a scrubbing/inspection port.

- **Pro:** keeps service available.
- **Con:** needs topology awareness and a valid alternate path.

### D. Temporary blocking

Ryu installs a block rule with a hard timeout, for example 300 seconds.

- **Pro:** stops the attack now and restores access automatically later.
- **Con:** still blocks during the timeout window.

### E. Dynamic high-priority rules

Security rules are installed at higher priority than normal forwarding rules.

```text
If a security rule matches -> apply mitigation first.
If nothing matches -> normal forwarding continues.
```

### Comparison and recommendation

| Method | Safety | Strength | Best used when |
| --- | --- | --- | --- |
| Drop | Low | High | High confidence, confirmed attacker |
| Rate limit | High | Medium | Uncertain predictions |
| Reroute | Medium | Medium | A safe alternate path exists |
| Temporary block | Medium-High | High | Confirmed attack, short-term response |
| High-priority rules | Support technique | N/A | Always, to ensure rules take effect |

**Safest recommended strategy for this project:**

```text
Low confidence  -> allow or monitor
Medium confidence -> rate-limit
High confidence + high link utilization -> temporary block
Alternate safe path available -> reroute legitimate traffic
```

This protects the network while minimizing harm to real users.

## 17. Complete Detection and Mitigation Flow

```text
Traffic generated
    -> OpenFlow switch
    -> Ryu collects flow/port statistics (or receives flow records)
    -> feature extraction
    -> preprocessing / scaling
    -> trained ENAS-optimized neural network
    -> normal / attack classification
    -> determine suspicious source + congested link
    -> mitigation decision
    -> Ryu sends OFPFlowMod / MeterMod
    -> switch blocks / rate-limits / reroutes traffic
    -> network statistics monitored again
```

**This loop repeats forever: observe, judge, act, observe again.**

## 18. Ryu Implementation Logic and Pseudocode

First the logic in plain words, then the pseudocode.

- `_monitor` runs on a timer and repeatedly asks switches for statistics.
- `_request_stats` sends the actual statistics requests.
- `_flow_stats_reply_handler` reads flow counters and builds per-flow context.
- `_port_stats_reply_handler` reads port counters and computes link utilization.
- `extract_features` turns raw flow data into the model input vector.
- `predict_attack` runs the model and returns probability and label.
- `identify_attacker` reads the flow's identity fields.
- `mitigate_attack` chooses and applies the response.
- `install_drop_rule` and `apply_rate_limit` send the OpenFlow commands.

```python
class SDNIDSController(RyuApp):
    def __init__(self):
        load_feature_pipeline()
        load_trained_model()
        load_mitigation_policy()
        initialize_switch_state()
        initialize_metrics()

    def _monitor(self):
        while True:
            for datapath in connected_switches:
                _request_stats(datapath)
            sleep(monitor_interval)

    def _request_stats(self, datapath):
        send OFPFlowStatsRequest to datapath
        send OFPPortStatsRequest to datapath

    def _flow_stats_reply_handler(self, event):
        for flow in event.flows:
            read match fields (src, dst, ports, protocol)
            read packet_count, byte_count, duration
            compute packet_rate and byte_rate
            store flow context

    def _port_stats_reply_handler(self, event):
        for port in event.ports:
            delta_bytes = tx_bytes_now - tx_bytes_before
            utilization = delta_bytes * 8 / (interval * link_bandwidth)
            if utilization > 0.8:
                mark_port_congested(port)

    def extract_features(self, raw_flow):
        mapped = map_field_names(raw_flow)
        filled = fill_missing_defaults(mapped)
        engineered = add_engineered_features(filled)
        vector = saved_preprocessing.transform(engineered)
        return vector

    def predict_attack(self, feature_vector):
        probability = model.predict(feature_vector)
        label = 1 if probability >= threshold else 0
        return probability, label

    def identify_attacker(self, raw_flow):
        return {
            "src_ip": raw_flow.srcIP,
            "dst_ip": raw_flow.dstIP,
            "src_port": raw_flow.srcPort,
            "dst_port": raw_flow.dstPort,
            "protocol": raw_flow.protocol,
            "dpid": raw_flow.dpid,
        }

    def mitigate_attack(self, identity, action):
        if action == "drop":
            install_drop_rule(identity)
        elif action == "rate_limit":
            apply_rate_limit(identity)
        elif action == "reroute":
            install_reroute_rule(identity)
        else:
            allow_or_monitor(identity)

    def install_drop_rule(self, identity):
        match = build_match(identity)
        send FlowMod(match=match, actions=[], priority=high, timeout=300)

    def apply_rate_limit(self, identity):
        meter_id = create_or_reuse_meter(rate_kbps=512)
        match = build_match(identity)
        send MeterMod(meter_id)
        send FlowMod(match=match, apply_meter=meter_id, priority=high)
```

## 19. Architecture Diagrams

### Offline training

```text
+--------------------------+
| Network Dataset          |
+------------+-------------+
             |
             v
+--------------------------+
| Preprocessing            |
+------------+-------------+
             |
             v
+--------------------------+
| GAN Augmentation         |
+------------+-------------+
             |
             v
+--------------------------+
| ENAS                     |
+------------+-------------+
             |
             v
+--------------------------+
| Optimized Neural Network |
+------------+-------------+
             |
             v
+--------------------------+
| Final Training           |
+------------+-------------+
             |
             v
+--------------------------+
| Saved ML Model           |
+--------------------------+
```

### Online detection

```text
+--------------------------+
| Mininet Hosts            |
+------------+-------------+
             |
             v
+--------------------------+     OpenFlow control     +------------------+
| OpenFlow Switches        | <----------------------> | Ryu Controller   |
+------------+-------------+                          +---------+--------+
             |                                                  |
             v                                                  |
+--------------------------+                                    |
| Statistics / Flow Records|                                    |
+------------+-------------+                                    |
             |                                                  |
             v                                                  |
+--------------------------+                                    |
| Feature Extraction       |                                    |
+------------+-------------+                                    |
             |                                                  |
             v                                                  |
+--------------------------+                                    |
| Preprocessing            |                                    |
+------------+-------------+                                    |
             |                                                  |
             v                                                  |
+--------------------------+                                    |
| Saved ML Model           |                                    |
+------------+-------------+                                    |
             |                                                  |
             v                                                  |
+--------------------------+                                    |
| Attack Prediction        |                                    |
+------------+-------------+                                    |
             |                                                  |
             v                                                  |
+--------------------------+                                    |
| Mitigation Engine        | <----------------------------------+
+------------+-------------+
             |
             v
+--------------------------+
| OpenFlow FlowMod/MeterMod|
+------------+-------------+
             |
             v
+--------------------------+
| Switches                 |
+------------+-------------+
             |
             v
+--------------------------+
| Drop / Rate Limit /      |
| Reroute                  |
+--------------------------+
```

## 20. A Full Numerical Attack Example

Setup:

```text
Link bandwidth = 100 Mbps
Target link = s2-s3
Legitimate users = h1, h2, h3
Attackers = h5, h6
Threshold = 0.5
```

### Normal condition

```text
Current utilization on s2-s3 = 35 Mbps  (35%)
Traffic looks diverse and healthy
ML attack probability = 0.10

Decision: 0.10 < 0.5 -> normal
Action: no mitigation, traffic flows freely
```

### Attack condition

```text
Current utilization on s2-s3 = 92 Mbps  (92%)
Many low-rate flows from h5 and h6 converge on s2-s3
ML attack probability for h5 flow = 0.96
ML attack probability for h6 flow = 0.94

Decision: probability > 0.5 AND utilization > 80% -> attack confirmed
Ryu marks h5 and h6 flows as suspicious
```

### Mitigation installed

```text
Rule 1:
  match: ipv4_src = 10.0.0.5, ipv4_dst = 10.0.0.10, tcp_dst = 80
  action: RATE_LIMIT (or DROP if high confidence)
  timeout: 300 seconds

Rule 2:
  match: ipv4_src = 10.0.0.6, ipv4_dst = 10.0.0.10, tcp_dst = 80
  action: RATE_LIMIT (or DROP if high confidence)
  timeout: 300 seconds
```

### Result after mitigation

```text
Before: s2-s3 utilization = 92 Mbps (congested)
After:  s2-s3 utilization = 48 Mbps (healthy)
Legitimate users h1, h2, h3 regain normal service
```

**Story version: the road was 92% blocked, Ryu throttled the two flooding sources, and the road dropped to 48% so ambulances (real users) could pass again.**

## 21. Interview and Viva Preparation

### 30-second explanation

My project detects and stops Link Flooding Attacks in an SDN network. Offline, I train a neural-network detector using flow features, GAN augmentation for more attack samples, and ENAS to choose the best model shape. Online, the Ryu controller watches OpenFlow switches, receives live flow features, runs the trained model, and installs OpenFlow rules to block, rate-limit, or reroute attack traffic.

### 1-minute explanation

The system has two pipelines. The offline pipeline prepares labelled flow data, uses a GAN to create extra realistic attack samples, and uses evolutionary neural architecture search to find the best MLP classifier. The final model and preprocessing are saved. The online pipeline runs in Ryu. Mininet hosts generate normal and attack traffic through OpenFlow switches. A flow extractor produces per-flow features and sends them to Ryu. Ryu applies the exact same preprocessing used during training, runs the model, and gets an attack probability. If the probability crosses a threshold, Ryu maps the prediction back to the flow's source, destination, ports, and switch, and installs FlowMod or MeterMod rules to mitigate the attack.

### 3-minute explanation

This project protects SDN networks from Link Flooding Attacks, where distributed attackers congest a shared link instead of directly attacking a server. It has an offline training phase and an online detection phase.

In training, I start with labelled flow data and split it into train, validation, and test sets before fitting any preprocessing, which prevents data leakage. Preprocessing creates port buckets, service flags, log-scaled numeric values, encoded categories, and scaled features, producing a 122-dimensional vector. Because stealthy LFA samples are limited, a GAN generates additional realistic attack samples. Then ENAS searches many candidate MLP architectures, varying layers, neurons, activations, dropout, learning rate, and batch size, scoring each on validation F1, and evolving better ones across generations. The best architecture is trained fully and saved.

In deployment, Ryu is the controller. OpenFlow switches carry traffic from normal and malicious Mininet hosts. A flow extractor such as Tranalyzer2 or CICFlowMeter turns packets into flow records, which are sent to Ryu. Ryu applies the saved preprocessing, runs the trained model, and obtains an attack probability. When a flow is suspicious, Ryu uses the flow's identity fields to know the source, destination, protocol, and switch, and combines this with link-utilization data to confirm congestion. It then installs OpenFlow rules to drop, rate-limit, or reroute the malicious traffic. GAN and ENAS are strictly offline; the live controller only loads and applies the finished model.

### 20 viva questions and answers

1. **How does Ryu actually detect the attack?** Ryu receives flow features, applies the saved preprocessing, runs the trained model, and checks the attack probability against a threshold.

2. **If ML detects the attack, what exactly is Ryu doing?** The model gives a probability; Ryu turns that into a network action by installing OpenFlow rules on switches.

3. **How do you identify the malicious host?** From the flow record's identity fields: source IP, destination IP, ports, protocol, and datapath ID.

4. **How is a flow mapped back to an attacker?** The same flow used for prediction carries the five-tuple, which Ryu places in the OpenFlow match.

5. **How do you detect which link is flooded?** Using port statistics and topology to find which saturated port carries many suspicious flows.

6. **How does Ryu mitigate the attack?** With FlowMod for drop/reroute and MeterMod for rate limiting, at high priority with timeouts.

7. **Why do you need GAN?** To create more realistic attack samples and improve detection of stealthy, underrepresented LFA traffic.

8. **Why use ENAS instead of manually designing an MLP?** ENAS objectively searches many architectures and selects the best by validation score, avoiding manual guesswork.

9. **Is GAN running during real-time detection?** No. GAN is offline training only; live detection uses the saved model.

10. **How do you avoid blocking legitimate users?** Use thresholds, combine ML with link utilization, prefer rate limiting when uncertain, and use temporary timeouts.

11. **What happens if the model produces a false positive?** A legitimate flow could be affected; using rate limiting and short timeouts reduces the harm.

12. **Why is F1-score important?** It balances precision and recall, so both false alarms and missed attacks are penalized, which matters for imbalanced security data.

13. **What is the difference between LFA and DDoS?** DDoS targets a server directly; LFA congests a shared link using low-rate, normal-looking flows.

14. **Why use SDN for this?** Centralized visibility and programmable control let the controller react instantly by reprogramming switches.

15. **What features detect LFA best?** Packet rate, byte rate, duration, packet-size and timing statistics, plus link utilization and flow convergence.

16. **Is CICFlowMeter required live?** Not strictly, but a flow extractor provides features matching the training schema, which improves accuracy.

17. **What does the saved model contain?** The trained weights and architecture metadata, reloaded by the Ryu application for inference.

18. **What is link utilization and how is it computed?** The fraction of link capacity used, from byte-counter changes over time divided by bandwidth.

19. **What is the safest mitigation?** Rate limiting for uncertain cases and temporary blocking for confirmed high-confidence attacks.

20. **What would you improve next?** Add temporal link-utilization features, path-level flow aggregation, threshold tuning, and LFA-focused retraining.

## 22. Common Misunderstandings to Avoid

- **Wrong:** "Ryu trains the model in real time." **Right:** Training is offline; Ryu only loads and uses the saved model.
- **Wrong:** "The ML model blocks the attacker." **Right:** The model predicts; Ryu installs the blocking rules.
- **Wrong:** "OpenFlow counters alone give all ML features." **Right:** A flow extractor supplies the rich features the model was trained on.
- **Wrong:** "GAN runs during detection." **Right:** GAN is a training-time augmentation tool.
- **Wrong:** "High accuracy means the model is great." **Right:** F1-score matters more when attacks are rare.
- **Wrong:** "One suspicious flow means an attack." **Right:** LFA is confirmed by many suspicious flows converging on a congested link.

## 23. Final Summary

- The project detects and mitigates Link Flooding Attacks in SDN.
- Offline, GAN augmentation and ENAS build a strong MLP detector.
- The detector and preprocessing are saved as artifacts.
- Online, Ryu observes traffic, applies the saved preprocessing, runs the model, and gets an attack probability.
- Ryu maps predictions back to real flows and links, then installs OpenFlow rules to drop, rate-limit, or reroute attack traffic.
- Combining ML predictions with link-utilization evidence reduces false positives.
- GAN and ENAS are offline; only the trained model runs live.

**One-line master summary: Train a smart detector offline with GAN and ENAS, then let the Ryu SDN controller use it live to spot flooded links and reprogram switches to protect real users.**
