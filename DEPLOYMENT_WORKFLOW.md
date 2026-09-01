# SDN IDS and LFA Evaluation Workflow

This document describes the complete workflow for training, deploying, testing, and evaluating the SDN intrusion-detection and Link Flooding Attack (LFA) mitigation system.

## 1. System Overview

The project has two phases:

1. Offline model training and evaluation in `sdn-security-framework1-FIXED.ipynb`.
2. Online SDN deployment using Ryu, Tranalyzer2, the trained models, and OpenFlow enforcement.

The live processing path is:

```text
Switch traffic
    -> mirrored/SPAN interface
    -> Tranalyzer2 per-flow output
    -> tranalyzer_watcher.py
    -> POST /ids/flow
    -> FeaturePipeline
    -> DetectionAgent
    -> static threshold or DQN mitigation policy
    -> OpenFlow allow, rate-limit, block, or reroute action
```

The controller cannot calculate precision, recall, or F1 from unlabelled live traffic. Those metrics require a ground-truth label for each flow from the traffic-generation test plan or an offline labelled simulation.

## 2. Project Contents

### Deployment code

- `deployment/ryu_ids_controller.py`: Ryu application, REST API, OpenFlow forwarding, detection, mitigation, and metrics.
- `deployment/model_inference.py`: detector, DQN policy, static policy, and synthetic LFA generator wrappers.
- `deployment/feature_pipeline.py`: reproduces the notebook's feature engineering and preprocessing.
- `deployment/tranalyzer_watcher.py`: reads Tranalyzer2 flow records and posts them to Ryu.
- `deployment/requirements.txt`: deployment Python dependencies.
- `deployment/setup.sh`: creates the deployment virtual environment and verifies artifacts.

### Training and evaluation

- `sdn-security-framework1-FIXED.ipynb`: preprocessing, ENAS model training, GAN augmentation, LFA generation, DQN mitigation, and offline evaluation.
- `data/final_binary_raw_dataset.csv`: raw training data. Required only for retraining.
- `results/`: saved LFA and DQN evaluation results.
- `artifacts/results/`: saved ENAS comparison results.

## 3. Required Runtime Artifacts

Preserve this directory structure. The deployment scripts resolve paths relative to the project root.

```text
sdn_notebook_final/
├── artifacts/
│   ├── processed/
│   │   ├── feature_columns.json
│   │   ├── label_encoder.pkl
│   │   ├── preprocessor.pkl
│   │   ├── train.npz
│   │   ├── val.npz
│   │   └── test.npz
│   ├── enas/
│   │   ├── best_architecture_gan.json
│   │   ├── best_architecture_no_gan.json
│   │   ├── best_model_gan.pt
│   │   └── best_model_no_gan.pt
│   ├── gan/
│   │   └── generator.pt
│   └── dqn_mitigation/
│       └── mitigation_policy.pt
└── deployment/
    ├── feature_pipeline.py
    ├── model_inference.py
    ├── requirements.txt
    ├── ryu_ids_controller.py
    ├── setup.sh
    └── tranalyzer_watcher.py
```

The raw `data/` directory is not needed for live inference. Include it only when the recipient must retrain the models.

## 4. Recommended Deployment Environment

Use a Linux host for the Ryu/OpenFlow deployment.

Recommended software:

- Python 3.8 or 3.9
- Ryu 4.34
- OpenFlow 1.3 switch or Open vSwitch
- Tranalyzer2
- PyTorch 2.x
- A mirrored or SPAN traffic interface

Ryu has compatibility issues with newer Python versions. Python 3.8 or 3.9 is preferred.

## 5. Transfer the Project

Example using `scp`:

```bash
scp -r sdn_notebook_final user@deployment-host:/opt/
```

Example using `rsync`:

```bash
rsync -av \
  deployment/ \
  artifacts/ \
  user@deployment-host:/opt/sdn_notebook_final/
```

After transfer, verify that `deployment/` and `artifacts/` are siblings under the project root.

## 6. Install Deployment Dependencies

On the deployment machine:

```bash
cd /opt/sdn_notebook_final/deployment
bash setup.sh
```

The setup script:

1. Selects Python 3.8, 3.9, or the available `python3`.
2. Creates `deployment/venv/`.
3. Installs the packages in `deployment/requirements.txt`.
4. Checks that the required model and preprocessing artifacts exist.

Activate the environment in every new terminal:

```bash
source /opt/sdn_notebook_final/deployment/venv/bin/activate
```

Verify the installation:

```bash
python -c "import torch, numpy, pandas, sklearn, joblib, ryu; print('dependencies OK')"
```

Verify artifacts:

```bash
cd /opt/sdn_notebook_final/deployment

python - <<'PY'
from pathlib import Path
import sys

root = Path("..")
required = [
    root / "artifacts/processed/preprocessor.pkl",
    root / "artifacts/processed/label_encoder.pkl",
    root / "artifacts/processed/feature_columns.json",
    root / "artifacts/processed/val.npz",
    root / "artifacts/processed/test.npz",
    root / "artifacts/enas/best_model_no_gan.pt",
    root / "artifacts/gan/generator.pt",
    root / "artifacts/dqn_mitigation/mitigation_policy.pt",
]

missing = [str(path) for path in required if not path.is_file()]
if missing:
    print("Missing artifacts:")
    print("\n".join(missing))
    sys.exit(1)

print("All runtime artifacts are present")
PY
```

## 7. Offline Notebook Workflow

The notebook [sdn-security-framework1-FIXED.ipynb](sdn-security-framework1-FIXED.ipynb) performs the training workflow.

Run it from the project root, not from `deployment/`:

```bash
cd /opt/sdn_notebook_final
python3 -m venv notebook-venv
source notebook-venv/bin/activate
pip install -r requirements.txt
jupyter notebook sdn-security-framework1-FIXED.ipynb
```

The notebook performs these steps:

1. Loads `data/final_binary_raw_dataset.csv`.
2. Creates leakage-safe train, validation, and test splits.
3. Fits preprocessing on the training split only.
4. Creates port buckets and service-port flags.
5. Applies log transforms to heavy-tailed flow statistics.
6. Encodes categorical values and scales numerical values.
7. Produces the 122-feature model input.
8. Searches for a suitable MLP architecture using ENAS.
9. Trains and evaluates the no-GAN detector.
10. Trains and evaluates the GAN-augmented detector.
11. Saves preprocessing files and detector checkpoints.
12. Trains the LFA generation/evasion component.
13. Trains the DQN mitigation policy.
14. Saves LFA and mitigation artifacts and result files.

Do not refit preprocessing during deployment. The live pipeline must use the saved `preprocessor.pkl`, `label_encoder.pkl`, and `feature_columns.json` generated by the notebook.

## 8. Start the Ryu Controller

On the controller host:

```bash
cd /opt/sdn_notebook_final/deployment
source venv/bin/activate
ryu-manager --observe-links ryu_ids_controller.py
```

The controller uses the default Ryu REST port:

```text
http://127.0.0.1:8080
```

At startup it loads:

- The fitted feature pipeline.
- `best_model_no_gan.pt` as the default detector.
- The static threshold policy by default.
- `generator.pt` for synthetic LFA simulation.

The controller default is:

```python
USE_DQN_POLICY = False
```

With this setting:

```text
P(attack) > 0.5  -> block
P(attack) <= 0.5 -> allow
```

To use the trained DQN mitigation policy, change it to:

```python
USE_DQN_POLICY = True
```

Test DQN enforcement in an isolated environment before using it on production traffic.

## 9. Connect an OpenFlow Switch

The switch must support OpenFlow 1.3 and be able to reach the Ryu controller.

For Open vSwitch:

```bash
sudo ovs-vsctl set bridge br0 protocols=OpenFlow13
sudo ovs-vsctl set-controller br0 tcp:<CONTROLLER_IP>:6633
sudo ovs-vsctl show
```

The Ryu log should show a connected switch and installed table-miss rules:

```text
Switch <DPID> connected, table-miss rules installed.
```

The controller uses:

- Table 0: security rules.
- Table 1: ordinary L2 forwarding.

The available enforcement actions are:

- `allow`
- `monitor`
- `rate_limit`
- `install_blocking_rule`
- `reroute`

Rerouting falls back to rate limiting unless a scrubbing or inspection port is configured in `ryu_ids_controller.py`:

```python
REROUTE_OUT_PORT = <SCRUBBING_PORT>
```

## 10. Configure Tranalyzer2

Tranalyzer2 must observe traffic through a mirrored/SPAN interface or an inline capture interface.

Example:

```bash
sudo t2 -i eth0 -w /var/log/t2/live -R 1
```

The exact flags can vary by Tranalyzer2 installation. The output must be continuously appended or rotated and must contain a header row.

Inspect the output:

```bash
head -2 /var/log/t2/live
```

The watcher expects fields such as:

```text
%dir flowStat ethType vlanID l4Proto srcPort dstPort duration
pktsSnt pktsRcvd l7BytesSnt l7BytesRcvd minL7PktSz maxL7PktSz
avgL7PktSz stdL7PktSz minIAT maxIAT avgIAT stdIAT pktps bytps
pktAsm bytAsm numHdrDesc numHdrs
```

If the output uses commas instead of tabs, pass:

```bash
--delimiter ','
```

The `tranalyzer_watcher.py` mapping may need adjustment if the local Tranalyzer2 configuration uses different column names.

## 11. Start the Tranalyzer2 Watcher

On the host that reads the Tranalyzer2 output:

```bash
cd /opt/sdn_notebook_final/deployment
source venv/bin/activate

python tranalyzer_watcher.py \
  --flow-file /var/log/t2/live \
  --controller http://192.168.1.10:8080 \
  --delimiter $'\t'
```

If the watcher and Ryu controller are on the same host:

```bash
python tranalyzer_watcher.py \
  --flow-file /var/log/t2/live \
  --controller http://127.0.0.1:8080
```

To enforce only on one switch:

```bash
python tranalyzer_watcher.py \
  --flow-file /var/log/t2/live \
  --controller http://192.168.1.10:8080 \
  --dpid 1
```

For every completed flow, the watcher:

1. Reads one Tranalyzer2 row.
2. Converts numeric values.
3. Maps Tranalyzer2 names to the deployment names.
4. Posts JSON to `/ids/flow`.
5. Prints the prediction and enforcement action.

## 12. REST API Checks

Check controller status:

```bash
curl -s http://127.0.0.1:8080/ids/status | python3 -m json.tool
```

Submit one test flow manually:

```bash
curl -s -X POST \
  http://127.0.0.1:8080/ids/flow \
  -H 'Content-Type: application/json' \
  -d '{
    "srcIP": "10.0.0.5",
    "dstIP": "10.0.0.10",
    "srcPort": 50001,
    "dstPort": 443,
    "l4Proto": 6,
    "%dir": "A",
    "flowStat": "0x0000000000000004",
    "ethType": "0x0800",
    "vlanID": null,
    "duration": 1.24,
    "pktsSnt": 14,
    "pktsRcvd": 11,
    "padBytesSnt": 0,
    "l7BytesSnt": 8210,
    "l7BytesRcvd": 5120,
    "minL7PktSz": 40,
    "maxL7PktSz": 1460,
    "avgL7PktSz": 586.4,
    "stdL7PktSz": 410.2,
    "minIAT": 0.0001,
    "maxIAT": 0.31,
    "avgIAT": 0.09,
    "stdIAT": 0.08,
    "pktps": 20.1,
    "bytps": 10740.3,
    "pktAsm": 0.12,
    "bytAsm": 0.23,
    "numHdrDesc": 1,
    "numHdrs": 3
  }' | python3 -m json.tool
```

The response contains an attack probability, predicted label, selected action, and current congestion value.

## 13. Run the Labelled LFA Simulation

The simulation is the most reproducible evaluation path because the labels are known.

Reset live counters:

```bash
curl -s -X POST \
  http://127.0.0.1:8080/ids/reset_metrics | python3 -m json.tool
```

Run a 256-flow test episode:

```bash
curl -s -X POST \
  http://127.0.0.1:8080/ids/simulate \
  -H 'Content-Type: application/json' \
  -d '{"n_flows": 256, "split": "test", "evasion_strength": 1.0}' \
  | python3 -m json.tool
```

Run a larger episode:

```bash
curl -s -X POST \
  http://127.0.0.1:8080/ids/simulate \
  -H 'Content-Type: application/json' \
  -d '{"n_flows": 10000, "split": "test", "evasion_strength": 1.0}' \
  | python3 -m json.tool
```

The default mix is:

```text
60% benign
20% real attack
20% synthetic LFA
```

The simulation returns:

- True positives, false positives, true negatives, and false negatives.
- Precision, recall, and F1-score.
- False mitigation and missed attack rates.
- LFA detection rate.
- Mean and final congestion.
- Action distribution.
- Mean prediction probabilities by population.
- Congestion trajectory.

## 14. Live Benign-Traffic Test

Use a controlled test network. Start the controller, switch, Tranalyzer2, and watcher first.

Reset counters:

```bash
curl -s -X POST http://127.0.0.1:8080/ids/reset_metrics
```

Generate only normal traffic for 15 to 30 minutes. Examples include:

```bash
curl http://<SERVER_IP>/
iperf3 -c <SERVER_IP> -t 900
```

Also include representative legitimate traffic such as DNS, HTTPS, SSH, ICMP, and file transfers.

Save operational metrics:

```bash
curl -s http://127.0.0.1:8080/ids/metrics > metrics_benign.json
```

The live endpoint reports flow counts, predicted attack counts, mean probability, action distribution, congestion, and the recent congestion trajectory.

## 15. Live Malicious and LFA Tests

Only generate malicious traffic in an isolated and authorized testbed.

Use separate runs:

```text
Run 1: benign traffic only, 15–30 minutes
Run 2: general attack traffic only, 15–30 minutes
Run 3: LFA traffic only, 15–30 minutes
Run 4: mixed traffic, 30–60 minutes
```

For every run, record:

- Test start and end time.
- Source and destination addresses.
- Protocol and ports.
- Traffic generator and parameters.
- Number of clients or attack sources.
- Attack rate.
- Ground-truth label.
- Controller checkpoint and policy.
- Detection threshold.

Reset before each run:

```bash
curl -s -X POST http://127.0.0.1:8080/ids/reset_metrics
```

Save results after each run:

```bash
curl -s http://127.0.0.1:8080/ids/metrics > metrics_lfa_run_01.json
```

A one-minute run is suitable as a smoke test, but it is too short for a reliable LFA evaluation. LFA is low-rate and distributed, so 15 to 30 minutes is a better minimum. One hour can be useful for stability testing, but duration alone does not fix a weak detector.

## 16. Metric Calculation for Real Traffic

The controller does not know the true class of a live flow. Join the traffic-generator log with the controller prediction log using a flow key such as:

```text
timestamp, srcIP, srcPort, dstIP, dstPort, l4Proto
```

For each flow define:

```text
actual_positive    = traffic-generator label is malicious
predicted_positive = controller selected a mitigation action
```

Calculate:

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * precision * recall / (precision + recall)
FMR       = FP / (TN + FP)
MAR       = FN / (TP + FN)
```

For LFA:

```text
LFA detection rate = correctly detected LFA flows / total LFA flows
```

Do not describe the unlabelled `/ids/metrics` output as precision or recall.

## 17. Performance Measurements

Collect three categories of measurements.

### Detection performance

- Accuracy
- Precision
- Recall
- F1-score
- ROC-AUC where available
- False mitigation rate
- Missed attack rate
- LFA detection rate
- Mean prediction probability for benign, general attack, and LFA flows

### Runtime performance

- Flows processed per second
- Mean and median inference latency
- REST request latency
- Tranalyzer2-to-controller delay
- CPU utilization
- Memory utilization
- OpenFlow rule-installation latency

### Network protection

- Link utilization before and after mitigation
- Attack throughput before and after mitigation
- Benign throughput before and after mitigation
- Packet loss
- Number of installed security rules
- Number of rate-limit meters
- Final and mean congestion

## 18. Current Results and Interpretation

The original ENAS detector test results are saved in `artifacts/results/comparison_results.json`. They show strong performance on the original binary dataset, with test F1 around 0.963 for the no-GAN model.

The LFA closed-loop results are saved in `results/full_lfa_pipeline_results.json`. They measure a different problem and should be reported separately. The LFA pipeline results indicate that:

- LFA detection before mitigation is approximately 54.6% in the recorded synthetic evaluation.
- The DQN mitigation policy can substantially reduce the post-mitigation missed-attack rate in the synthetic simulation.
- Synthetic LFA results must be confirmed using controlled live traffic.
- The controller uses the static threshold policy unless `USE_DQN_POLICY` is enabled.

The binary detector metrics and LFA closed-loop mitigation metrics must not be presented as one identical experiment.

## 19. Recommended Experimental Repetitions

For a conference-quality evaluation:

1. Run each traffic condition at least three times.
2. Use independent traffic seeds or source sets.
3. Report the number of flows, not only elapsed time.
4. Report the benign-to-attack class balance.
5. Report the threshold and model checkpoint.
6. Report the hardware and software versions.
7. Include confidence intervals or standard deviations.
8. Compare static threshold and DQN policies.
9. Compare no-GAN and GAN detector checkpoints.
10. Evaluate LFA at multiple rates and numbers of attack sources.

## 20. Troubleshooting

### Controller cannot load a checkpoint

Check that the project root has the expected `artifacts/` directories and that Ryu is started from `deployment/`.

### Feature dimension mismatch

The live preprocessing must use the same `preprocessor.pkl` and feature schema created by the notebook. Do not manually change the feature order.

### Watcher posts errors

Inspect the Tranalyzer2 header and compare it with `T2_COLUMN_MAP` in `tranalyzer_watcher.py`. Confirm the delimiter.

### No flows are being scored

Check:

```bash
curl -s http://127.0.0.1:8080/ids/status | python3 -m json.tool
```

Then verify that:

- Tranalyzer2 is seeing packets.
- The flow output file is growing.
- The watcher is running.
- The watcher points to the correct controller IP and port.
- The controller accepts requests on port 8080.

### No mitigation is visible

Confirm that a switch is connected, the DPID is correct if `--dpid` is used, and the selected action is not `allow` or `monitor`. Check the Ryu log for flow-mod errors.

### High LFA missed-attack rate

Evaluate threshold tuning first, then consider LFA-focused retraining, temporal/link-utilization features, additional LFA traffic diversity, and comparison of the GAN and no-GAN checkpoints.

## 21. Minimal Startup Sequence

For a normal deployment, the commands are:

```bash
# Terminal 1: Ryu controller
cd /opt/sdn_notebook_final/deployment
source venv/bin/activate
ryu-manager --observe-links ryu_ids_controller.py
```

```bash
# Terminal 2: Tranalyzer2
sudo t2 -i eth0 -w /var/log/t2/live -R 1
```

```bash
# Terminal 3: flow watcher
cd /opt/sdn_notebook_final/deployment
source venv/bin/activate
python tranalyzer_watcher.py \
  --flow-file /var/log/t2/live \
  --controller http://127.0.0.1:8080
```

```bash
# Terminal 4: status and metrics
curl -s http://127.0.0.1:8080/ids/status | python3 -m json.tool
curl -s http://127.0.0.1:8080/ids/metrics | python3 -m json.tool
```

## 22. Complete Operational Runbook

Use this section as the exact checklist for a new deployment. Complete each phase in order and do not proceed when a check fails.

### 22.1 Assign machine roles

The components may run on one host for a small lab, but separate hosts are preferred for a realistic test.

| Role | Responsibility | Required software |
| --- | --- | --- |
| Controller host | Runs Ryu, model inference, REST API, and OpenFlow mitigation | Python, Ryu, PyTorch, project artifacts |
| Switch host | Forwards test traffic and applies OpenFlow rules | Open vSwitch or OpenFlow 1.3 switch |
| Capture host | Receives mirrored traffic and runs Tranalyzer2 plus the watcher | Tranalyzer2, Python, Requests |
| Client hosts | Generate normal application traffic | `curl`, `iperf3`, browser, DNS/SSH clients |
| Test coordinator | Starts and stops tests and stores ground-truth records | Shell, `curl`, timestamped logs |

For an all-in-one lab, the controller, capture process, and switch may share one Linux machine. The network interface captured by Tranalyzer2 must still receive the actual test traffic.

### 22.2 Record network values before starting

Write these values into the experiment record before the first test:

```text
Project directory:       /opt/sdn_notebook_final
Controller IP:           <CONTROLLER_IP>
Ryu OpenFlow port:       6633
Ryu REST port:           8080
Switch bridge name:      <BRIDGE_NAME>
Switch DPID:             <DPID>
Capture interface:       <CAPTURE_INTERFACE>
Tranalyzer output file:  <T2_FLOW_FILE>
Detector checkpoint:     best_model_no_gan.pt or best_model_gan.pt
Mitigation policy:       static_threshold or dqn
Detection threshold:     0.5 unless deliberately changed
Test date and timezone:  <DATE_TIMEZONE>
```

Find local interfaces and IP addresses:

```bash
ip addr
ip link
```

Find the Open vSwitch bridge and controller assignment:

```bash
sudo ovs-vsctl show
sudo ovs-vsctl get-controller <BRIDGE_NAME>
```

### 22.3 Check network reachability and firewall rules

The switch needs TCP access to the controller's OpenFlow port. The capture host needs HTTP access to the controller REST endpoint.

From the capture host:

```bash
curl -s http://<CONTROLLER_IP>:8080/ids/status | python3 -m json.tool
```

From the switch host, test the controller port:

```bash
nc -vz <CONTROLLER_IP> 6633
```

If a firewall is enabled, permit only the test network to reach the relevant ports:

```text
TCP 6633: OpenFlow switch -> Ryu controller
TCP 8080: watcher/test coordinator -> Ryu REST API
```

Do not expose the REST API to an untrusted network. `/ids/flow` can cause enforcement actions and `/ids/simulate` consumes controller resources.

### 22.4 Make an experiment directory

Create one directory per run so logs, metrics, traffic-generator records, and configuration are not mixed.

```bash
export RUN_ID="$(date +%Y%m%d_%H%M%S)_baseline"
export RUN_DIR="$HOME/sdn_ids_runs/$RUN_ID"
mkdir -p "$RUN_DIR"
```

Store the configuration used for the run:

```bash
cp /opt/sdn_notebook_final/deployment/ryu_ids_controller.py "$RUN_DIR/"
cp /opt/sdn_notebook_final/deployment/tranalyzer_watcher.py "$RUN_DIR/"
cp /opt/sdn_notebook_final/artifacts/enas/best_architecture_no_gan.json "$RUN_DIR/"
python --version > "$RUN_DIR/python_version.txt"
pip freeze > "$RUN_DIR/pip_freeze.txt"
```

Record the source revision when the project is a Git repository:

```bash
git -C /opt/sdn_notebook_final rev-parse HEAD > "$RUN_DIR/git_commit.txt"
git -C /opt/sdn_notebook_final status --short > "$RUN_DIR/git_status.txt"
```

### 22.5 Install and verify before connecting traffic

On the controller host:

```bash
cd /opt/sdn_notebook_final/deployment
chmod +x setup.sh
bash setup.sh
source venv/bin/activate
python -c "import torch, numpy, pandas, sklearn, joblib, ryu; print('dependencies OK')"
```

Confirm the selected detector, GAN generator, and preprocessing files exist:

```bash
ls -lh \
  ../artifacts/processed/preprocessor.pkl \
  ../artifacts/processed/label_encoder.pkl \
  ../artifacts/processed/feature_columns.json \
  ../artifacts/enas/best_model_no_gan.pt \
  ../artifacts/gan/generator.pt \
  ../artifacts/dqn_mitigation/mitigation_policy.pt
```

Confirm that preprocessing produces the expected 122 features:

```bash
cd /opt/sdn_notebook_final/deployment
source venv/bin/activate
python feature_pipeline.py
```

The expected final line is:

```text
OK - matches the 122-feature training schema.
```

### 22.6 Configure controller behavior deliberately

Before starting Ryu, review these settings in `deployment/ryu_ids_controller.py`:

```python
DETECTOR_CKPT = PROJECT_ROOT / "artifacts" / "enas" / "best_model_no_gan.pt"
USE_DQN_POLICY = False
RATE_LIMIT_KBPS = 512
BLOCK_HARD_TIMEOUT = 300
REROUTE_OUT_PORT = None
```

Use the no-GAN checkpoint unless the GAN checkpoint has been independently evaluated on the same testbed. Keep `USE_DQN_POLICY = False` for the first connectivity and benign tests; it makes behaviour easy to interpret because the policy blocks only when prediction probability exceeds 0.5.

Only enable DQN after confirming that the saved `mitigation_policy.pt` is present and the testbed can safely accept automatic rate limits or blocks:

```python
USE_DQN_POLICY = True
```

Set `REROUTE_OUT_PORT` only when that port is verified to lead to a working scrubbing or inspection path. Otherwise reroute degrades to rate limiting.

### 22.7 Start components in this order

Use separate terminals or a supervised service manager. Save all standard output and errors.

Terminal 1, Ryu controller:

```bash
cd /opt/sdn_notebook_final/deployment
source venv/bin/activate
ryu-manager --observe-links ryu_ids_controller.py 2>&1 | tee "$RUN_DIR/ryu.log"
```

Terminal 2, switch connection:

```bash
sudo ovs-vsctl set bridge <BRIDGE_NAME> protocols=OpenFlow13
sudo ovs-vsctl set-controller <BRIDGE_NAME> tcp:<CONTROLLER_IP>:6633
sudo ovs-vsctl show | tee "$RUN_DIR/ovs_show.txt"
```

Terminal 3, Tranalyzer2 capture:

```bash
sudo mkdir -p /var/log/t2
sudo t2 -i <CAPTURE_INTERFACE> -w /var/log/t2/live -R 1 2>&1 | tee "$RUN_DIR/tranalyzer.log"
```

Terminal 4, watcher:

```bash
cd /opt/sdn_notebook_final/deployment
source venv/bin/activate
python tranalyzer_watcher.py \
  --flow-file <T2_FLOW_FILE> \
  --controller http://<CONTROLLER_IP>:8080 \
  --dpid <DPID> \
  --delimiter $'\t' 2>&1 | tee "$RUN_DIR/watcher.log"
```

If the watcher must apply rules to every connected switch, omit `--dpid`.

### 22.8 Confirm each component before testing

Controller health:

```bash
curl -s http://<CONTROLLER_IP>:8080/ids/status | tee "$RUN_DIR/status_before.json" | python3 -m json.tool
```

Confirm these fields:

```text
connected_switches: contains the expected DPID
lfa_generator_loaded: true
flows_scored: 0 before traffic is sent
policy: static_threshold or dqn as intended
```

Confirm the Tranalyzer2 file exists and contains a header:

```bash
ls -lh <T2_FLOW_FILE>
head -n 2 <T2_FLOW_FILE>
```

Confirm the watcher is posting completed flows by generating one harmless request and checking its terminal output. The watcher should print one `NORMAL` or `ATTACK` line after the flow completes.

### 22.9 Capture a baseline before enforcement tests

First verify that ordinary forwarding works without IDS mitigation. Temporarily stop the watcher, or do not send any completed capture flows to the controller. Test host-to-host reachability and normal application traffic.

```bash
ping -c 4 <SERVER_IP>
curl -I http://<SERVER_IP>/
iperf3 -c <SERVER_IP> -t 30
```

Then start the watcher and repeat. This establishes whether a forwarding issue belongs to the base OpenFlow configuration or to IDS enforcement.

### 22.10 Run a controller-only labelled simulation

This test does not require a switch, capture interface, or traffic generator. It validates detector, LFA generator, policy, and metric calculation.

```bash
curl -s -X POST \
  http://<CONTROLLER_IP>:8080/ids/simulate \
  -H 'Content-Type: application/json' \
  -d '{"n_flows": 256, "split": "test", "evasion_strength": 1.0}' \
  | tee "$RUN_DIR/simulation_256.json" | python3 -m json.tool
```

Repeat with a larger sample for a more stable simulated estimate:

```bash
curl -s -X POST \
  http://<CONTROLLER_IP>:8080/ids/simulate \
  -H 'Content-Type: application/json' \
  -d '{"n_flows": 10000, "split": "test", "evasion_strength": 1.0}' \
  | tee "$RUN_DIR/simulation_10000.json" | python3 -m json.tool
```

Do not treat this synthetic result as a substitute for real-network LFA testing.

### 22.11 Run a benign-only live test

1. Reset controller counters.
2. Record the start time.
3. Generate only authorized normal traffic for 15 to 30 minutes.
4. Save controller metrics and all logs.
5. Record the end time and total generated flows.

```bash
curl -s -X POST http://<CONTROLLER_IP>:8080/ids/reset_metrics \
  | tee "$RUN_DIR/reset_benign.json"

date --iso-8601=seconds | tee "$RUN_DIR/benign_start.txt"
iperf3 -c <SERVER_IP> -t 900 | tee "$RUN_DIR/benign_iperf3.txt"
date --iso-8601=seconds | tee "$RUN_DIR/benign_end.txt"

curl -s http://<CONTROLLER_IP>:8080/ids/metrics \
  | tee "$RUN_DIR/metrics_benign.json" | python3 -m json.tool
```

Supplement the throughput test with the legitimate protocols that matter to the target environment. Keep a record of each client and traffic type.

### 22.12 Run an authorized general-attack test

Perform this only in an isolated, approved test network. Create a ground-truth record before sending traffic:

```text
Run ID:
Class: ATTACK
Attack family:
Source IPs:
Destination IPs:
Start time:
End time:
Rate and parameters:
Expected flow identifiers:
```

Reset metrics immediately before the run, save the traffic-generator output, and fetch `/ids/metrics` immediately after. Use the same duration and baseline workload as the benign test where possible.

### 22.13 Run an authorized LFA test

An LFA test must use multiple controlled sources that create low-rate traffic toward a chosen bottleneck or target. The exact generator depends on the lab topology, so preserve its command, source list, rate, target, and time interval in the ground-truth record.

Recommended initial design:

```text
Duration: 15 to 30 minutes
Attack sources: 3 or more independent clients
Background traffic: present and recorded
Target: one intentionally provisioned bottleneck path
Traffic rate: low enough that individual flows resemble normal traffic
Repetitions: at least 3 independent runs
```

One minute is a smoke test only. A longer test provides more completed flows and lets low-rate congestion behaviour emerge, but it does not improve model quality by itself. Use 30 to 60 minutes for endurance and stability experiments after the 15 to 30 minute tests work reliably.

### 22.14 Retrieve and preserve results after every run

Always collect the status and metrics before resetting counters for the next run:

```bash
curl -s http://<CONTROLLER_IP>:8080/ids/status \
  | tee "$RUN_DIR/status_after.json" | python3 -m json.tool

curl -s http://<CONTROLLER_IP>:8080/ids/metrics \
  | tee "$RUN_DIR/metrics_after.json" | python3 -m json.tool
```

Also retain:

```text
Ryu log
Watcher log
Tranalyzer2 log and flow export
Open vSwitch configuration and flow table dump
Traffic-generator log
Ground-truth labels
Configuration copy and package versions
Start/end timestamps
```

Dump OpenFlow rules after the test:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows <BRIDGE_NAME> \
  | tee "$RUN_DIR/ovs_flows_after.txt"
sudo ovs-ofctl -O OpenFlow13 dump-meters <BRIDGE_NAME> \
  | tee "$RUN_DIR/ovs_meters_after.txt"
```

### 22.15 Calculate valid live-test metrics

The controller returns predictions and actions, but it does not receive the true live label. Match every controller-scored flow to the traffic-generator ground-truth record using time, source IP, source port, destination IP, destination port, and protocol.

Classify a flow as mitigated when its selected action is one of:

```text
rate_limit
install_blocking_rule
reroute
```

Then compute the confusion matrix:

```text
TP: malicious flow mitigated
FP: benign flow mitigated
TN: benign flow not mitigated
FN: malicious flow not mitigated
```

Report both raw counts and these metrics:

```text
precision = TP / (TP + FP)
recall = TP / (TP + FN)
F1 = 2 * precision * recall / (precision + recall)
accuracy = (TP + TN) / (TP + FP + TN + FN)
false mitigation rate = FP / (FP + TN)
missed attack rate = FN / (FN + TP)
LFA detection rate = correctly mitigated LFA flows / total LFA flows
```

When a denominator is zero, report that metric as not applicable rather than as zero.

### 22.16 Compare experiments fairly

Use the same topology, controller host, model, traffic duration, background traffic, LFA source count, target path, and ground-truth rules for every comparison. Change one independent variable at a time.

Recommended comparisons:

```text
Static threshold policy vs DQN policy
No-GAN detector vs GAN detector
Threshold values around the current 0.5 value
Different LFA rates and source counts
With and without background traffic
Short (15 min) vs endurance (60 min) test windows
```

For every configuration, run at least three repetitions and report the mean, standard deviation, minimum, and maximum for each key metric.

### 22.17 Stop safely and remove temporary enforcement

At the end of an experiment:

1. Stop traffic generation.
2. Stop the watcher with `Ctrl+C`.
3. Stop Tranalyzer2 with `Ctrl+C`.
4. Save status, metrics, and switch rule dumps.
5. Stop Ryu with `Ctrl+C`.
6. Remove test-specific flow rules and meters from the switch if the lab requires a clean reset.

For a disposable Open vSwitch lab bridge, clearing flows can be done with:

```bash
sudo ovs-ofctl -O OpenFlow13 del-flows <BRIDGE_NAME>
```

Only run this on a dedicated test bridge. It removes all flows on that bridge, including normal forwarding rules.

To detach the test controller when finished:

```bash
sudo ovs-vsctl del-controller <BRIDGE_NAME>
```

### 22.18 Handoff acceptance criteria

The deployment is ready to hand over when all items below are true:

- `bash setup.sh` completes without missing artifacts.
- `python feature_pipeline.py` reports a `(1, 122)` output vector.
- Ryu starts without checkpoint or preprocessing errors.
- `/ids/status` reports `lfa_generator_loaded: true`.
- The intended switch DPID appears in `connected_switches`.
- A Tranalyzer2 flow file is produced with the expected header.
- The watcher posts completed flows successfully.
- `/ids/simulate` returns labelled simulation metrics.
- A benign test completes without unintended blocking being ignored.
- A controlled attack test produces visible prediction and mitigation records.
- Logs, metrics JSON, switch dumps, and ground-truth traffic records are saved for each run.
