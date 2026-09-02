# Project Architecture Explanation for Interview, Review, and Viva

Project title:

```text
Evolutionary Neural Architecture Search with GAN-Augmented Training for
Link Flooding Attack Detection in Software-Defined Networks
```

This document explains the complete architecture, module responsibilities, training pipeline, real-time detection pipeline, mitigation process, and interview/viva answers for the SDN-based IDS project.

## 1. Complete System Architecture

The project combines Software-Defined Networking (SDN) with machine learning. SDN provides centralized control through the Ryu controller and OpenFlow switches. Machine learning provides flow-level attack detection.

The conceptual end-to-end architecture is:

```text
Normal users / attackers
    -> Mininet hosts
    -> OpenFlow switches
    -> Ryu controller
    -> flow-statistics or flow-record collection
    -> feature extraction
    -> preprocessing
    -> GAN augmentation during training
    -> ENAS architecture optimization during training
    -> trained neural-network IDS model
    -> real-time attack prediction
    -> Ryu mitigation module
    -> OpenFlow rules installed on switches
```

There are two different architectures in the project.

### Offline ML training architecture

Offline training builds the model before deployment:

```text
Raw labelled dataset
    -> cleaning and feature engineering
    -> train/validation/test split
    -> fitted preprocessing pipeline
    -> GAN attack-sample augmentation
    -> ENAS model search
    -> final MLP training
    -> evaluation
    -> saved model and preprocessing artifacts
```

This phase uses the notebook and saved datasets. It does not need live Ryu control to run.

### Online SDN detection architecture

Online detection uses the trained model inside the deployed SDN system:

```text
Live Mininet or SDN traffic
    -> OpenFlow switches
    -> mirrored/SPAN capture
    -> flow extractor such as Tranalyzer2 or CICFlowMeter
    -> watcher posts flow JSON to Ryu
    -> Ryu applies saved preprocessing
    -> saved MLP predicts attack probability
    -> mitigation policy chooses action
    -> Ryu sends FlowMod or MeterMod
    -> switch blocks, rate-limits, monitors, or reroutes traffic
```

Important implementation detail: this project currently uses Tranalyzer2-style flow records posted to Ryu through `/ids/flow`. Ryu still controls OpenFlow switches and mitigation, but the ML features come from a flow extractor because the trained model expects richer fields than basic OpenFlow counters provide.

### Training vs real-time detection

| Component | Training | Real-time detection |
| --- | --- | --- |
| Raw labelled dataset | Used | Not required |
| Preprocessing fit | Used | Not refit |
| Saved preprocessing | Produced | Loaded and reused |
| GAN | Used for augmentation | Not required for every live prediction |
| ENAS | Searches best architecture | Not run live |
| MLP detector | Trained and saved | Loaded for inference |
| Ryu controller | Not required | Required |
| OpenFlow switches | Not required | Required for mitigation |
| Flow extractor | Used for dataset/features | Used for live flow features |
| Mitigation module | Evaluated or trained offline | Runs in Ryu |

The simple explanation is: GAN and ENAS improve the model offline; Ryu uses the saved model online to detect and mitigate attacks.

## 2. Every Module or Agent

Technically, most pieces should be called modules, components, or pipeline stages. The word agent is acceptable for presentation when a component performs a specialized role, but in a technical viva it is safer to say:

```text
The system is composed of modules. Some modules are agent-like, such as the LFA generator and mitigation policy, because they generate or decide actions, but they are implemented as software components.
```

### Traffic Generation Module

Responsibility: create normal and malicious traffic in Mininet.

Input: Mininet topology, host list, traffic plan, attack parameters.

Processing: normal hosts send legitimate traffic; attacker hosts send coordinated low-rate traffic.

Output: packets injected into the SDN network and ground-truth test labels.

Receiver: OpenFlow switches and the flow extractor.

Runs during: evaluation and real-time testing. It is not needed for offline training unless generating a new dataset.

### Data Collection Module

Responsibility: collect flow-level information from network traffic.

Input: captured packets or switch statistics.

Processing: groups packets into flows and computes counters and timing statistics.

Output: flow records.

Receiver: feature extraction module.

Runs during: dataset creation and real-time detection.

### Feature Extraction Module

Responsibility: convert raw network observations into ML feature values.

Input: Tranalyzer2 or CICFlowMeter flow records, or equivalent statistics.

Processing: extracts source/destination fields, ports, protocol, packet counts, byte counts, duration, rates, packet-size statistics, and inter-arrival-time values.

Output: raw feature dictionary or table row.

Receiver: preprocessing module.

Runs during: both training and inference.

### Preprocessing Module

Responsibility: apply exactly the same transformations used during training.

Input: raw flow feature dictionary and saved preprocessing artifacts.

Processing: fills missing values, buckets ports, adds service-port flags, applies log transforms, encodes categoricals, scales numerics, and preserves feature order.

Output: fixed-size numerical vector, currently 122 features.

Receiver: ML detection module.

Runs during: training for fitting; inference for transformation only.

### GAN Augmentation Module

Responsibility: create synthetic attack samples to improve training diversity.

Input: real attack samples and random noise vectors.

Processing: generator creates synthetic samples; discriminator judges real vs synthetic; both improve through adversarial training.

Output: synthetic attack feature vectors.

Receiver: classifier training pipeline.

Runs during: offline training and optional simulation, not normal live detection.

### ENAS Optimization Module

Responsibility: search for the best neural-network architecture.

Input: training/validation sets and architecture search space.

Processing: creates candidate MLP architectures, trains briefly, evaluates fitness, selects parents, performs crossover and mutation, repeats generations.

Output: best architecture configuration.

Receiver: final model training.

Runs during: offline training only.

### ML Detection Module

Responsibility: classify flows as normal or attack-like.

Input: preprocessed feature vector.

Processing: runs the trained MLP and applies a threshold to the attack probability.

Output: attack probability and normal/attack label.

Receiver: attack detection and mitigation logic.

Runs during: offline evaluation and real-time inference.

### Ryu Monitoring Module

Responsibility: maintain SDN control-plane visibility.

Input: OpenFlow switch events, PacketIn events, optional flow and port statistics replies.

Processing: registers switches, learns MAC-to-port mappings, installs default forwarding behavior, and can collect switch statistics.

Output: switch state, forwarding state, and link/port context.

Receiver: detection and mitigation modules.

Runs during: real-time SDN operation.

### Attack Detection Module

Responsibility: decide whether a flow or source is suspicious.

Input: ML probability, flow identity, optional congestion/link utilization.

Processing: compares probability to threshold and can combine it with link-utilization evidence.

Output: normal/suspicious decision and action recommendation.

Receiver: mitigation module.

Runs during: real-time detection.

### Mitigation Module

Responsibility: convert detection into network action.

Input: suspicious flow identity and selected action.

Processing: builds OpenFlow match fields and sends FlowMod or MeterMod messages.

Output: installed switch rules.

Receiver: OpenFlow switches.

Runs during: real-time mitigation.

### OpenFlow Rule Management Module

Responsibility: install, update, and expire switch rules.

Input: match fields, priority, action, timeout, meter rate.

Processing: creates high-priority security rules and rate-limit meters.

Output: switch-level forwarding changes.

Receiver: OpenFlow datapath.

Runs during: real-time mitigation.

## 3. Traffic Generation

In Mininet, hosts emulate users, attackers, and servers. OpenFlow switches emulate the SDN data plane. Ryu is the centralized controller.

Example topology:

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

Normal hosts send ordinary traffic such as HTTP, DNS, SSH, ICMP, or file-transfer traffic. Their destinations, rates, ports, and durations are diverse.

Malicious hosts coordinate low-rate traffic so their flows converge on a target link, for example `s2-s3`. Each individual attack flow may appear harmless, but together they consume the bottleneck link.

LFA differs from normal DDoS because the main target is often a network link rather than the final server. A traditional DDoS overwhelms a server or service directly. LFA tries to congest a shared path so legitimate users cannot reach the service even if the server itself is healthy.

## 4. Ryu Controller Monitoring

Ryu talks to OpenFlow switches using OpenFlow messages.

| Message | Direction | Purpose |
| --- | --- | --- |
| `PacketIn` | Switch to Ryu | Sent when a packet has no matching switch rule. |
| `FlowMod` | Ryu to switch | Installs, modifies, or deletes flow rules. |
| `OFPFlowStatsRequest` | Ryu to switch | Requests flow-table statistics. |
| `OFPFlowStatsReply` | Switch to Ryu | Returns flow counters and match information. |
| `OFPPortStatsRequest` | Ryu to switch | Requests per-port statistics. |
| `OFPPortStatsReply` | Switch to Ryu | Returns byte, packet, drop, and error counters. |
| `MeterMod` | Ryu to switch | Adds or modifies rate-limiting meters. |

A typical periodic monitoring workflow is:

```text
Ryu sends OFPFlowStatsRequest
    -> switch replies with OFPFlowStatsReply
    -> Ryu extracts flow match fields and counters
    -> Ryu sends OFPPortStatsRequest
    -> switch replies with OFPPortStatsReply
    -> Ryu calculates packet rates, byte rates, and link utilization
    -> features or link context are passed to detection logic
```

Flow statistics can provide source IP, destination IP, source port, destination port, protocol, packet count, byte count, duration, table ID, priority, and sometimes input port if it is part of the rule match.

Port statistics can provide received bytes, transmitted bytes, packet counts, dropped packets, errors, and port numbers.

Important accuracy point: this exact deployment does not depend only on OpenFlow flow statistics for the ML model because the trained feature schema includes fields such as packet-size and inter-arrival-time features. Those are better obtained from a flow extractor. Ryu still uses OpenFlow for visibility and mitigation.

## 5. Feature Extraction

Feature extraction converts traffic into numerical values for the ML model.

Useful LFA features include:

- Packet rate.
- Byte rate.
- Flow duration.
- Number of flows.
- Source diversity.
- Destination diversity.
- Packet size.
- Inter-arrival time.
- Flow asymmetry.
- Port utilization.
- Link utilization.
- Many suspicious flows sharing one link.

Ryu can calculate some features directly from OpenFlow counters:

```text
packet_rate = delta_packets / delta_time
byte_rate = delta_bytes / delta_time
flow_duration = duration_sec + duration_nsec
```

However, CICFlowMeter or Tranalyzer2 can compute richer packet-derived features. For this project, the best architecture is hybrid:

```text
Flow extractor -> rich ML features -> Ryu model inference
Ryu OpenFlow stats -> link utilization and switch/port context
Ryu OpenFlow rules -> mitigation
```

This preserves feature consistency with training and still uses SDN control for action.

## 6. GAN Augmentation

GAN augmentation is used because attack samples, especially LFA samples, may be fewer and less diverse than normal traffic samples. Without enough diverse attack examples, the classifier may learn only obvious attacks and miss subtle low-rate attacks.

The generator receives random noise and produces synthetic attack-like feature vectors. The discriminator receives real and synthetic samples and learns to distinguish them. The generator improves by trying to fool the discriminator.

Training process:

```text
1. Select real attack samples.
2. Generate synthetic attack samples from random noise.
3. Train discriminator to distinguish real vs synthetic.
4. Train generator to make more realistic attack samples.
5. Combine real training data with synthetic attack samples.
6. Train the IDS classifier on the augmented data.
```

GAN is mainly offline. It is not required each time Ryu classifies a live flow. In this project, the saved generator can also support controlled LFA simulation, but live detection uses the saved detector.

## 7. Evolutionary Neural Architecture Search

ENAS searches for a good MLP architecture automatically. Instead of manually choosing layers and hyperparameters, it evolves candidate architectures.

Candidate parameters include:

- Number of hidden layers.
- Number of neurons.
- Activation function.
- Learning rate.
- Dropout.
- Batch size.

Workflow:

```text
Initial population of candidate architectures
    -> brief training for each candidate
    -> validation scoring using F1-score or accuracy
    -> select best candidates
    -> crossover combines good traits
    -> mutation explores new settings
    -> next generation
    -> repeat
    -> select best architecture
```

Example:

```text
Generation 1:
Architecture A -> F1 = 0.86
Architecture B -> F1 = 0.89
Architecture C -> F1 = 0.84

Selection + crossover + mutation

Generation 2:
Architecture D -> F1 = 0.91
Architecture E -> F1 = 0.92

Best architecture E is selected for final training.
```

In the saved no-GAN result, the selected architecture is a ReLU-based MLP with multiple hidden layers and dropout.

## 8. Final ML Model

Final model training follows this path:

```text
Dataset
    -> preprocessing
    -> train/test split
    -> optional GAN augmentation
    -> ENAS architecture selection
    -> final MLP training
    -> evaluation
    -> model saved as .pt checkpoint
    -> Ryu application loads the checkpoint
```

The result of approximately 96% accuracy means most flows in the binary test set were classified correctly. An F1-score around 0.92 or higher means the model balances precision and recall well.

F1-score is important because IDS datasets can be imbalanced. Accuracy alone may hide missed attacks. F1 forces the model to perform well on both:

```text
precision = how many predicted attacks were truly attacks
recall = how many real attacks were detected
```

## 9. Real-Time Detection Using Ryu

Step-by-step runtime flow:

```text
1. Ryu starts and loads preprocessing artifacts and the saved ML model.
2. OpenFlow switches connect to Ryu.
3. Ryu installs default table-miss and forwarding rules.
4. Mininet hosts send normal or attack traffic.
5. Flow extractor converts packets into flow records.
6. Watcher sends each flow record to Ryu through POST /ids/flow.
7. Ryu applies the same preprocessing/scaling used during training.
8. Ryu sends the feature vector into the trained MLP.
9. The model outputs an attack probability.
10. If probability crosses the threshold, the flow is suspicious.
11. Ryu identifies the source/destination/protocol of the suspicious flow.
12. Ryu installs a mitigation rule on the switch.
```

Example output interpretation:

```text
P(attack) = 0.08 -> normal
P(attack) = 0.92 -> attack
```

The current static policy is:

```text
P(attack) > 0.5 -> block
P(attack) <= 0.5 -> allow
```

## 10. How Ryu Identifies the Attacker

The ML model only predicts whether the feature vector looks malicious. Ryu identifies the responsible flow using the metadata attached to that feature vector.

Important flow identifiers:

```text
source IP
destination IP
source port
destination port
protocol
switch datapath ID
input/output port when available
timestamp
```

If the feature vector for this flow is malicious:

```text
srcIP = 10.0.0.5
dstIP = 10.0.0.10
srcPort = 50120
dstPort = 80
l4Proto = 6
dpid = 1
```

Ryu can install a rule matching that five-tuple on switch `dpid=1`. For distributed LFA, Ryu groups suspicious flows by shared link, switch, port, destination, or path. A single suspicious flow may not prove LFA, but many suspicious flows converging on the same congested link is stronger evidence.

## 11. Link Utilization Detection

Link utilization can be calculated from port counters:

```text
Utilization = (current_tx_bytes - previous_tx_bytes) * 8
              / (time_interval * link_bandwidth_bits_per_second)
```

Example:

```text
previous_tx_bytes = 100,000,000
current_tx_bytes = 111,500,000
delta = 11,500,000 bytes
interval = 1 second
bandwidth = 100 Mbps

utilization = 11,500,000 * 8 / 100,000,000 = 0.92 = 92%
```

LFA decision logic can combine:

```text
link utilization > 80%
+ ML model predicts attack
+ many suspicious flows use the same link
=> Link Flooding Attack detected
```

Combining ML prediction with link utilization usually reduces false positives because mitigation is triggered only when suspicious traffic also affects the network.

## 12. Attack Mitigation

Ryu mitigates by programming switches. It sends commands; switches enforce them.

### A. Drop flow

Ryu sends a high-priority FlowMod rule with a match and no output action.

```text
match: source IP = attacker, destination IP = target, protocol/port
action: DROP
```

This is fast but can harm legitimate users if the prediction is wrong.

### B. Rate limiting

Ryu installs an OpenFlow meter and applies it to suspicious traffic.

```text
match: suspicious flow
action: apply meter, then forward
```

This is safer than dropping because the traffic is reduced rather than fully blocked.

### C. Rerouting

Ryu redirects traffic through another path or inspection port. This is useful when an alternate path exists but requires topology awareness.

### D. Temporary blocking

Ryu installs a block rule with a hard timeout, such as 300 seconds. This avoids permanent lockout.

### E. Dynamic high-priority rules

Security rules are installed with higher priority than normal forwarding rules. Suspicious traffic matches the security rule first; other traffic follows normal forwarding.

Recommended safe strategy:

```text
Low confidence -> allow or monitor
Medium confidence -> rate-limit
High confidence + high link utilization -> temporary block
Known safe alternate path -> reroute
```

## 13. Complete Detection and Mitigation Flow

```text
Traffic generated
    -> OpenFlow switch
    -> flow extractor creates flow record
    -> watcher sends flow JSON to Ryu
    -> Ryu preprocesses features
    -> trained ENAS-optimized MLP predicts normal/attack
    -> suspicious source and congested link are identified
    -> mitigation decision is selected
    -> Ryu sends OFPFlowMod or MeterMod
    -> switch blocks, rate-limits, or reroutes traffic
    -> statistics are monitored again
```

## 14. Ryu Implementation Logic and Pseudocode

Logic first: Ryu maintains switch state, receives or requests network statistics, transforms flow information into ML features, calls the trained model, identifies the suspicious flow, and installs mitigation rules.

Simplified pseudocode:

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
            sleep(interval)

    def _request_stats(self, datapath):
        send OFPFlowStatsRequest
        send OFPPortStatsRequest

    def _flow_stats_reply_handler(self, event):
        for flow in event.reply:
            extract match fields
            extract byte_count and packet_count
            calculate packet_rate and byte_rate
            store flow context

    def _port_stats_reply_handler(self, event):
        for port in event.reply:
            calculate link utilization
            mark overloaded ports

    def extract_features(self, raw_flow):
        map flow fields
        fill missing values
        apply saved preprocessing
        return feature_vector

    def predict_attack(self, feature_vector):
        probability = model.predict(feature_vector)
        label = probability >= threshold
        return probability, label

    def identify_attacker(self, raw_flow):
        return srcIP, dstIP, srcPort, dstPort, protocol, dpid

    def mitigate_attack(self, flow_identity, action):
        if action == "drop":
            install_drop_rule(flow_identity)
        elif action == "rate_limit":
            apply_rate_limit(flow_identity)
        elif action == "reroute":
            install_reroute_rule(flow_identity)

    def install_drop_rule(self, flow_identity):
        match = build_openflow_match(flow_identity)
        send FlowMod with empty action list

    def apply_rate_limit(self, flow_identity):
        send MeterMod to create meter
        send FlowMod that applies meter
```

## 15. Architecture Diagram

Offline training:

```text
Network Dataset
    -> Preprocessing
    -> GAN Augmentation
    -> ENAS
    -> Optimized Neural Network
    -> Final Training
    -> Saved ML Model and Preprocessor
```

Online detection:

```text
Mininet Hosts
    -> OpenFlow Switches
    <-> Ryu Controller
    -> Statistics / Flow Record Collection
    -> Feature Extraction
    -> Preprocessing
    -> Saved ML Model
    -> Attack Prediction
    -> Mitigation Engine
    -> OpenFlow FlowMod / MeterMod
    -> Switches
    -> Drop / Rate Limit / Reroute
```

Detailed view:

```text
+----------------------+        +----------------------+
| Offline Training     |        | Online Detection     |
+----------------------+        +----------------------+
| Labelled dataset     |        | Mininet hosts        |
| Preprocessing        |        | OpenFlow switches    |
| GAN augmentation     |        | Ryu controller       |
| ENAS architecture    |        | Flow extractor       |
| Final MLP training   |        | Saved preprocessor   |
| Saved artifacts      | -----> | Saved ML detector    |
+----------------------+        | Mitigation engine    |
                                | FlowMod / MeterMod   |
                                +----------------------+
```

## 16. Example Attack Scenario

Normal condition:

```text
Link bandwidth = 100 Mbps
Current utilization = 35 Mbps
Utilization = 35%
ML attack probability = 0.10
Decision = normal
Action = no mitigation
```

Attack condition:

```text
Link bandwidth = 100 Mbps
Current utilization = 92 Mbps
Utilization = 92%
Suspicious flows from h5 and h6 converge on s2-s3
ML attack probability for h5 = 0.96
ML attack probability for h6 = 0.94
Decision = attack
```

Ryu installs temporary mitigation rules:

```text
Rule 1:
match ipv4_src=10.0.0.5, ipv4_dst=10.0.0.10, tcp_dst=80
action DROP or RATE_LIMIT
timeout 300 seconds

Rule 2:
match ipv4_src=10.0.0.6, ipv4_dst=10.0.0.10, tcp_dst=80
action DROP or RATE_LIMIT
timeout 300 seconds
```

After mitigation:

```text
Before mitigation utilization = 92 Mbps
After mitigation utilization = 48 Mbps
Legitimate traffic experiences lower delay and packet loss
```

## 17. Interview and Viva Explanation

### 30-second explanation

My project detects and mitigates Link Flooding Attacks in an SDN network. Offline, I train a neural-network IDS using flow features, GAN augmentation for attack diversity, and ENAS to select the best MLP architecture. Online, Ryu controls OpenFlow switches, receives live flow features from a flow extractor, applies the saved preprocessing and trained model, predicts attack probability, and installs OpenFlow rules to block, rate-limit, or reroute suspicious traffic.

### 1-minute explanation

The system has an offline ML pipeline and an online SDN pipeline. Offline, labelled flow data is preprocessed, augmented with GAN-generated attack samples, and used by ENAS to find a good MLP architecture. The final model and preprocessing pipeline are saved. Online, Mininet hosts send normal and attack traffic through OpenFlow switches controlled by Ryu. A flow extractor creates per-flow records and sends them to Ryu. Ryu converts each flow to the same feature format used during training and runs the saved detector. If the attack probability crosses a threshold, Ryu maps the prediction back to the source IP, destination IP, ports, protocol, and switch, then installs FlowMod or MeterMod rules for mitigation.

### 3-minute explanation

The architecture is divided into training and deployment. During training, I use labelled network-flow data and split it into train, validation, and test sets before fitting preprocessing to avoid data leakage. The preprocessing creates port buckets, service-port flags, log-transformed numerical values, categorical encodings, and scaled numeric features. Because LFA traffic can be subtle and underrepresented, GAN augmentation creates additional attack-like samples. ENAS then searches candidate MLP architectures by varying layers, neurons, activations, dropout, learning rate, and batch size. Candidate models are scored on validation performance, and the best architecture is trained fully and saved.

During deployment, Ryu acts as the SDN controller. OpenFlow switches carry traffic from normal and malicious Mininet hosts. A flow extractor observes traffic and generates flow records. The watcher posts these records to Ryu. Ryu applies the saved preprocessing, runs the trained MLP, and receives an attack probability. If traffic is suspicious, Ryu uses the original flow identity to decide which source, destination, protocol, and switch rule should be affected. It then sends OpenFlow FlowMod or MeterMod messages so the switch can block, rate-limit, or reroute the traffic. For LFA, the strongest design combines ML probability with link-utilization evidence, because LFA is about many flows congesting a shared link rather than only one host attacking a server.

## 18. Likely Viva Questions and Answers

1. What is the main goal of the project?

   To detect and mitigate Link Flooding Attacks in an SDN environment using ML-based flow classification and Ryu-based OpenFlow control.

2. What is a Link Flooding Attack?

   It is an attack where distributed sources send traffic that converges on and congests a target network link, often without directly overwhelming the final server.

3. How is LFA different from DDoS?

   DDoS usually targets a server or service directly. LFA targets the network path or bottleneck link and may use low-rate flows that look normal individually.

4. Why use SDN?

   SDN gives centralized visibility and programmable control, allowing the controller to install rules dynamically when an attack is detected.

5. What does Ryu do?

   Ryu controls OpenFlow switches, handles forwarding, receives flow records for ML inference, tracks metrics, and installs mitigation rules.

6. How does Ryu actually detect the attack?

   Ryu receives flow features, applies the saved preprocessing pipeline, sends the feature vector to the trained MLP, and checks the attack probability.

7. If ML detects the attack, what exactly is Ryu doing?

   ML produces the prediction. Ryu converts that prediction into network enforcement by installing OpenFlow rules.

8. How do you identify the malicious host?

   The suspicious flow record contains source IP, destination IP, ports, protocol, and optionally datapath ID. Ryu uses these fields to identify and match the traffic.

9. How is a flow mapped back to an attacker?

   The feature vector is generated from a flow record that still carries the five-tuple. Ryu uses that five-tuple in the mitigation rule.

10. How do you detect which link is flooded?

    By using port statistics, topology information, and grouping suspicious flows that traverse the same switch port or path.

11. What is link utilization?

    It is the fraction of link bandwidth being used, calculated from byte-counter changes over time divided by link capacity.

12. Why do you need GAN?

    GAN improves attack-sample diversity and helps the classifier learn subtle attack patterns when real LFA examples are limited.

13. Is GAN running during real-time detection?

    No. GAN is mainly offline. The live controller uses the saved detector, not the GAN training loop.

14. Why use ENAS instead of manually designing an MLP?

    ENAS systematically searches architectures and chooses one based on validation performance instead of relying on manual guessing.

15. What is the final classifier?

    An ENAS-selected MLP trained on preprocessed flow features, optionally with GAN-augmented attack samples.

16. Why is F1-score important?

    F1 balances precision and recall, which matters because IDS systems must avoid both false alarms and missed attacks.

17. How do you avoid blocking legitimate users?

    Use thresholds carefully, combine ML with link-utilization evidence, prefer rate limiting for uncertain cases, and use temporary timeouts.

18. What happens if the model has a false positive?

    A legitimate flow may be mitigated. The impact can be reduced using rate limiting, monitoring, and temporary rules instead of permanent drops.

19. What OpenFlow messages are used for mitigation?

    FlowMod is used for drop, forward, or reroute rules. MeterMod is used for rate limiting.

20. What is the strongest future improvement?

    Add stronger LFA-specific features such as temporal link utilization, path-level aggregation, threshold tuning, and LFA-focused retraining.

## 19. Strong Short Answer for the Most Important Viva Question

Question:

```text
How does your Ryu controller actually detect and mitigate LFA?
```

Answer:

```text
Ryu is the SDN control-plane component. It does not train the model in real time.
The trained model is produced offline using preprocessing, GAN augmentation, and
ENAS. During deployment, live traffic is converted into flow records by a flow
extractor. Ryu receives those records, applies the same saved preprocessing used
during training, and sends the feature vector into the saved MLP detector. The
model outputs an attack probability. Ryu maps that prediction back to the
original flow identity, such as source IP, destination IP, ports, protocol, and
datapath. If the probability is high, especially when link utilization is also
high, Ryu installs OpenFlow FlowMod or MeterMod rules so the switch blocks,
rate-limits, or reroutes the suspicious traffic.
```

## 20. What Not to Say

Do not say:

```text
Ryu trains the GAN or ENAS model in real time.
```

Say instead:

```text
GAN and ENAS are offline training components. Ryu only loads the saved model for real-time inference and mitigation.
```

Do not say:

```text
OpenFlow flow statistics always provide all ML features.
```

Say instead:

```text
OpenFlow statistics provide useful counters and link context, but this project uses richer flow-extractor features to match the training schema.
```

Do not say:

```text
The ML model directly blocks attackers.
```

Say instead:

```text
The ML model predicts attack probability. Ryu performs mitigation by installing OpenFlow rules on switches.
```
