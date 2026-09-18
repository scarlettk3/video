#!/usr/bin/env python3
"""Ryu controller for the user's unchanged NSFNET Mininet topology.

Features
--------
* OpenFlow 1.3 forwarding on the exact 13-switch/13-host NSFNET graph.
* Real-time flow/port statistics.
* ENAS/SD-CGAN detector deployment from the exported notebook artifacts.
* Entropy-weighted dynamic routing using utilization, configured link delay,
  observed port-drop loss, and traffic-contribution entropy.
* Conventional shortest-path and congestion-aware routing modes for comparison.
* REST IDS ingestion (/ids/flow), metrics (/ids/metrics), robustness stress test
  (/ids/simulate), routing mode selection, and live routing comparison.
* Live terminal/JSON/CSV metrics including inference, processing, response,
  throughput, packet loss, jitter, latency, CPU, memory, core link utilization,
  evasion degradation, robustness retention, and controller overhead.

Legacy-compatible run command:
    ryu-manager --ofp-tcp-listen-port 6633 ryu_ids_controller.py

The exact NSFNET switch-port map is initialized statically from the supplied
Nsfnet.py, so --observe-links is optional rather than required.

The Mininet topology itself is not modified by this controller.
"""
from __future__ import annotations

import csv
import heapq
import json
import math
import os
import pickle
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np
import psutil
from webob import Response

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import arp, ethernet, ether_types, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event

from sdcgan_runtime import SDCGANRuntime

APP_INSTANCE = "nsfnet_sdcgan_app"

# ---------------------------------------------------------------------------
# Exact NSFNET graph from the supplied Nsfnet.py.  No Mininet topology change.
# Host hN is attached to switch sN and all city links are 128 Mbps.
# ---------------------------------------------------------------------------
NSFNET_LINKS = {
    (1, 3): 5.7301,
    (1, 12): 6.7101,
    (1, 8): 10.6415,
    (2, 3): 5.7520,
    (2, 5): 1.4156,
    (4, 13): 1.8972,
    (5, 13): 3.0254,
    (6, 10): 8.1465,
    (6, 7): 5.7441,
    (7, 13): 16.7352,
    (7, 8): 3.5271,
    (9, 10): 2.8798,
    (10, 12): 7.3524,
    (11, 12): 3.6408,
    (12, 13): 2.2703,
}
CORE_LINK_BW_MBPS = 128.0
MAX_STATIC_DELAY_MS = max(NSFNET_LINKS.values())
HOST_IP_TO_SWITCH = {f"10.0.0.{i}": i for i in range(1, 14)}
HOST_PORT = 1  # host links are added before all inter-switch links in Nsfnet.py

# Controlled-experiment ground-truth convention, matching tranalyzer_watcher.py
# --label-by-ip defaults. Used so the Ryu controller itself can populate
# accuracy/precision/recall/F1/confusion-matrix/ROC even when nobody runs the
# external watcher (see NSFNetSDCGANController._auto_ground_truth).
DEFAULT_ATTACK_IPS = "10.0.0.1,10.0.0.2,10.0.0.3"
DEFAULT_NORMAL_IPS = "10.0.0.4,10.0.0.5,10.0.0.6"

# Deterministic OVS port numbering from the *unchanged* Nsfnet.py link-add order.
# This lets the controller use the same Ryu command as the user's previous
# workflow; LLDP/--observe-links may refine these mappings but is not required.
STATIC_LINK_PORTS = {
    (1, 3): (2, 2),
    (1, 12): (3, 2),
    (1, 8): (4, 2),
    (2, 3): (2, 3),
    (2, 5): (3, 2),
    (4, 13): (2, 2),
    (5, 13): (3, 3),
    (6, 10): (2, 2),
    (6, 7): (3, 2),
    (7, 13): (3, 4),
    (7, 8): (4, 3),
    (9, 10): (2, 3),
    (10, 12): (4, 3),
    (11, 12): (2, 4),
    (12, 13): (5, 5),
}

NETWORK_METRICS_DIR = Path("/tmp/sdn_ids_metrics")
NETWORK_METRICS_PATH = NETWORK_METRICS_DIR / "session_network_metrics.json"
SESSION_ACTIVE_FLAG = NETWORK_METRICS_DIR / "session_active.flag"
SESSION_STOP_FLAG = NETWORK_METRICS_DIR / "session_stop.flag"
RYU_METRICS_JSON = NETWORK_METRICS_DIR / "ryu_live_metrics.json"
RYU_METRICS_CSV = NETWORK_METRICS_DIR / "ryu_live_metrics.csv"
EVAL_JSON = NETWORK_METRICS_DIR / "live_detection_evaluation.json"
EVAL_PREDICTIONS_CSV = NETWORK_METRICS_DIR / "live_detection_predictions.csv"
EVAL_CONFUSION_CSV = NETWORK_METRICS_DIR / "live_confusion_matrix.csv"
EVAL_ROC_CSV = NETWORK_METRICS_DIR / "live_roc_curve.csv"


def edge_key(a: int, b: int) -> Tuple[int, int]:
    return (a, b) if a < b else (b, a)


def ewma_append(store: deque, value: Optional[float]) -> None:
    if value is not None and math.isfinite(float(value)):
        store.append(float(value))


def avg(values: Sequence[float]) -> Optional[float]:
    return float(sum(values) / len(values)) if values else None


def safe_round(value: Optional[float], digits: int = 6) -> Optional[float]:
    return None if value is None else round(float(value), digits)


def shannon_normalized(contributions: Mapping[str, float]) -> float:
    vals = np.asarray([v for v in contributions.values() if v > 0], dtype=float)
    if vals.size <= 1 or vals.sum() <= 0:
        return 0.0
    p = vals / vals.sum()
    h = float(-np.sum(p * np.log(p + 1e-12)))
    return float(h / np.log(len(vals)))


class NSFNetSDCGANController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        wsgi.register(NSFNetRestController, {APP_INSTANCE: self})

        package_dir = Path(__file__).resolve().parent
        artifact_dir = Path(os.getenv("SDCGAN_ARTIFACT_DIR", package_dir / "artifacts" / "ryu"))
        device = os.getenv("SDCGAN_DEVICE", "cpu")
        self.detector = SDCGANRuntime(artifact_dir, device=device)
        with open(artifact_dir / "mitigation_config.pkl", "rb") as fh:
            self.mitigation_cfg = pickle.load(fh)

        self.test_npz = Path(os.getenv(
            "SDCGAN_TEST_NPZ",
            package_dir / "artifacts" / "preprocessed" / "test.npz",
        ))

        self.routing_mode = os.getenv("SDN_ROUTING_MODE", "entropy").strip().lower()
        if self.routing_mode not in {"entropy", "shortest", "congestion", "learned"}:
            self.routing_mode = "entropy"
        self.learning_policy = self._load_learning_policy(os.getenv("SDN_LEARNING_POLICY"))
        if self.routing_mode == "learned" and self.learning_policy is None:
            self.logger.warning("SDN_ROUTING_MODE=learned requested but no SDN_LEARNING_POLICY was loaded; falling back to entropy")
            self.routing_mode = "entropy"

        self.stats_interval = float(self.mitigation_cfg.get("stats_poll_interval", 1.0))
        self.entropy_window = float(self.mitigation_cfg.get("entropy_window_seconds", 5.0))
        self.reference_entropy = float(self.mitigation_cfg.get("example_reference_entropy", 0.5))
        self.route_hysteresis = float(os.getenv("SDN_ROUTE_HYSTERESIS", "0.10"))
        # NOTE: these two used to default to "0" (blocking disabled) and 0.995
        # (a bar almost no real prediction reaches, since the detector's own
        # decision threshold below is 0.5). That combination meant mitigation
        # silently degraded to "reroute only" even when SDN_BLOCK_ATTACKS=1 was
        # set, because the block condition could basically never fire. Default
        # blocking on, and default the confidence bar to the detector's own
        # threshold so "detected as attack" and "eligible to be blocked" agree
        # unless the operator intentionally raises SDN_BLOCK_THRESHOLD.
        self.block_attacks = os.getenv("SDN_BLOCK_ATTACKS", "1") == "1"
        self.block_threshold = float(os.getenv("SDN_BLOCK_THRESHOLD", str(self.detector.threshold)))
        self.block_seconds = int(os.getenv("SDN_BLOCK_SECONDS", "10"))
        self.suspicion_decay_seconds = float(os.getenv("SDN_SUSPICION_DECAY_SECONDS", "30.0"))

        # Automatic ground-truth labeling for the controlled NSFNET experiment.
        # Without this, /ids/flow calls coming from raw OpenFlow port/flow
        # stats (source="openflow_stats") never carry a ground_truth, so
        # eval_true/eval_pred never get populated and accuracy/precision/
        # recall/F1/confusion-matrix/ROC stay empty forever -- exactly what
        # entropy_run.csv shows (detection_count/attack_count grow every
        # second, labeled_flows stays 0). Enabled by default for the
        # documented h1-h3 attack / h4-h6 normal experiment; set
        # SDN_AUTO_LABEL_BY_IP=0 to disable for real/unlabeled traffic.
        self.auto_label_by_ip = os.getenv("SDN_AUTO_LABEL_BY_IP", "1") == "1"
        self.auto_label_attack_ips = {
            ip.strip() for ip in os.getenv("SDN_ATTACK_IPS", DEFAULT_ATTACK_IPS).split(",") if ip.strip()
        }
        self.auto_label_normal_ips = {
            ip.strip() for ip in os.getenv("SDN_NORMAL_IPS", DEFAULT_NORMAL_IPS).split(",") if ip.strip()
        }
        # Reverse map: which physical switch is each labeled host attached to.
        # This is what makes labeling/blocking work under spoofed source IPs
        # (see packet_in_handler and _auto_ground_truth/_mitigate_attack) --
        # a switch a host is wired into can't be forged the way an IP header
        # can. Only meaningful for the controlled experiment's known hosts.
        self.auto_label_switch_roles: Dict[int, int] = {}
        for ip in self.auto_label_attack_ips:
            sw = HOST_IP_TO_SWITCH.get(ip)
            if sw is not None:
                self.auto_label_switch_roles[sw] = 1
        for ip in self.auto_label_normal_ips:
            sw = HOST_IP_TO_SWITCH.get(ip)
            if sw is not None:
                self.auto_label_switch_roles[sw] = 0
        # (src_ip, dst_ip) -> (true ingress dpid, monotonic timestamp). TTL is
        # kept close to the 15s idle_timeout used by _install_path so a cache
        # entry doesn't outlive the OpenFlow flow it describes.
        self.flow_origin: Dict[Tuple[str, str], Tuple[int, float]] = {}
        self.flow_origin_ttl = float(os.getenv("SDN_FLOW_ORIGIN_TTL_SECONDS", "30.0"))
        # Per-IP ground-truth override: ip -> (role, monotonic_expiry). Lets you
        # run "attack from a normally-trusted host" experiments (e.g. h6
        # launching an attack) without touching SDN_ATTACK_IPS/SDN_NORMAL_IPS
        # or restarting the controller -- see /ids/label_override. Checked
        # before the static IP table in _auto_ground_truth, so it always wins
        # while active; the static h1-h3/h4-h6 convention still applies to
        # every host you haven't explicitly overridden.
        self.label_overrides: Dict[str, Tuple[int, float]] = {}

        self.datapaths: Dict[int, Any] = {}
        self.mac_to_port: Dict[int, Dict[str, int]] = defaultdict(dict)
        self.ip_to_mac: Dict[str, str] = {}
        self.port_to_neighbor: Dict[Tuple[int, int], int] = {}
        self.link_ports: Dict[Tuple[int, int], Tuple[int, int]] = {}
        # Preload exact port mapping from Nsfnet.py so the legacy command
        # `ryu-manager --ofp-tcp-listen-port 6633 ryu_ids_controller.py` works
        # without requiring --observe-links.
        for (u, v), (pu, pv) in STATIC_LINK_PORTS.items():
            self.port_to_neighbor[(u, pu)] = v
            self.port_to_neighbor[(v, pv)] = u
            self.link_ports[(u, v)] = (pu, pv)
            self.link_ports[(v, u)] = (pv, pu)
        self.blocked_ports: set[Tuple[int, int]] = set()

        self.prev_port: Dict[Tuple[int, int], Tuple[float, int, int, int, int, int, int]] = {}
        self.port_rate_mbps: Dict[Tuple[int, int], float] = {}
        self.port_loss_percent: Dict[Tuple[int, int], float] = {}
        self.prev_flow: Dict[Tuple[Any, ...], Tuple[float, int, int]] = {}
        self.link_contrib: Dict[Tuple[int, int], deque] = defaultdict(deque)
        self.installed_routes: Dict[Tuple[str, str], Dict[str, Any]] = {}
        # src_ip -> (max_attack_probability_seen, monotonic_last_seen). Fed
        # into _mitigation_penalty() so entropy/congestion/learned routing
        # actively steers new paths away from links currently carrying a
        # flagged attacker's traffic, instead of only depending on the
        # optional hard block below.
        self.suspicious_sources: Dict[str, Tuple[float, float]] = {}

        self.metric_series = {
            "inference_time_ms": deque(maxlen=200),
            "processing_time_ms": deque(maxlen=200),
            "response_time_s": deque(maxlen=200),
            "controller_overhead_ms": deque(maxlen=200),
        }
        self.last_detection: Dict[str, Any] = {}
        self.evasion_degradation_percentage: Optional[float] = None
        self.robustness_retention_percent: Optional[float] = None

        # Live supervised evaluation is populated only when /ids/flow includes
        # a ground-truth label. The supplied watcher can add labels for the
        # controlled Mininet experiment (h1-h3 attack, h4-h6 normal).
        self.eval_true: List[int] = []
        self.eval_score: List[float] = []
        self.eval_pred: List[int] = []
        self.eval_tn = self.eval_fp = self.eval_fn = self.eval_tp = 0
        self._roc_cache: Dict[str, Any] = {"roc_auc": None, "fpr": [], "tpr": [], "thresholds": []}
        self._roc_cache_n = 0
        self._roc_cache_time = 0.0

        self.detection_count = 0
        self.attack_count = 0
        self.start_time = time.time()

        self.process = psutil.Process(os.getpid())
        self.process.cpu_percent(None)
        self._metrics_lock = threading.RLock()
        self._prepare_session_dir()

        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.live_thread = hub.spawn(self._live_metrics_loop)
        self.logger.info(
            "ENAS/SD-CGAN loaded: input_dim=%d threshold=%.3f routing_mode=%s "
            "block_attacks=%s block_threshold=%.3f auto_label_by_ip=%s "
            "attack_ips=%s normal_ips=%s",
            self.detector.input_dim,
            self.detector.threshold,
            self.routing_mode,
            self.block_attacks,
            self.block_threshold,
            self.auto_label_by_ip,
            ",".join(sorted(self.auto_label_attack_ips)),
            ",".join(sorted(self.auto_label_normal_ips)),
        )

    # ---------------------------- setup helpers ----------------------------
    def _prepare_session_dir(self) -> None:
        NETWORK_METRICS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(NETWORK_METRICS_DIR), 0o777)
        except OSError:
            pass
        if os.getenv("SDN_RESET_SESSION_FLAGS", "1") == "1":
            for p in (SESSION_ACTIVE_FLAG, SESSION_STOP_FLAG):
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass

    def _load_learning_policy(self, path: Optional[str]) -> Any:
        if not path:
            return None
        p = Path(path).expanduser()
        if not p.exists():
            self.logger.warning("Learning policy not found: %s", p)
            return None
        try:
            with open(p, "rb") as fh:
                policy = pickle.load(fh)
            self.logger.info("Loaded optional learning-based routing policy: %s", p)
            return policy
        except Exception as exc:
            self.logger.exception("Could not load learning policy %s: %s", p, exc)
            return None

    # -------------------------- OpenFlow plumbing --------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        # Ask for port descriptions so blocked/STP ports can be excluded.
        dp.send_msg(parser.OFPPortDescStatsRequest(dp, 0))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        idle_timeout=0,
        hard_timeout=0,
        cookie=0x53444347,
    ):
        parser, ofp = datapath.ofproto_parser, datapath.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_reply_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        for p in ev.msg.body:
            if p.port_no >= ofp.OFPP_MAX:
                continue
            blocked = bool(p.state & getattr(ofp, "OFPPS_BLOCKED", 0))
            key = (dp.id, p.port_no)
            if blocked:
                self.blocked_ports.add(key)
            else:
                self.blocked_ports.discard(key)

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        link = ev.link
        u, v = int(link.src.dpid), int(link.dst.dpid)
        self.port_to_neighbor[(u, int(link.src.port_no))] = v
        self.link_ports[(u, v)] = (int(link.src.port_no), int(link.dst.port_no))

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        link = ev.link
        u, v = int(link.src.dpid), int(link.dst.dpid)
        self.port_to_neighbor.pop((u, int(link.src.port_no)), None)
        self.link_ports.pop((u, v), None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg, dp = ev.msg, ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port[dp.id][eth.src] = in_port
        ip4 = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        if ip4:
            self.ip_to_mac[ip4.src] = eth.src
            # packet_in only fires here because THIS switch had a table miss
            # for this exact 5-tuple; _install_path() then proactively installs
            # the same match at every hop, so no other switch along the path
            # will ever see a table miss for it. That makes dp.id at this
            # exact moment the true, unspoofable physical entry point of this
            # flow -- unlike ip4.src, which an attacker fully controls (e.g.
            # hping3 --rand-source). Cache it so _auto_ground_truth() and
            # _mitigate_attack() can use it instead of trusting ipv4_src.
            self.flow_origin[(ip4.src, ip4.dst)] = (int(dp.id), time.monotonic())
        elif arp_pkt:
            self.ip_to_mac[arp_pkt.src_ip] = eth.src

        # ARP/non-IPv4 remains ordinary learning/flood forwarding.  IPv4 uses
        # the NSFNET routing graph when topology discovery has learned ports.
        if ip4 and ip4.dst in HOST_IP_TO_SWITCH:
            match_fields = self._packet_match_fields(pkt, ip4)
            path = self._best_path(int(dp.id), HOST_IP_TO_SWITCH[ip4.dst], self.routing_mode)
            if path and self._path_ports_ready(path):
                self._install_path(ip4.src, ip4.dst, path, match_fields)
                out_port = HOST_PORT if len(path) == 1 else self._out_port(path[0], path[1])
                if out_port is not None:
                    self._packet_out(msg, in_port, out_port)
                    return

        # L2 fallback. This also makes ARP work while LLDP discovery converges.
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
            self.add_flow(dp, 5, match, actions, idle_timeout=20)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        dp.send_msg(out)

    def _packet_match_fields(self, pkt, ip4) -> Dict[str, Any]:
        fields = {
            "eth_type": ether_types.ETH_TYPE_IP,
            "ipv4_src": ip4.src,
            "ipv4_dst": ip4.dst,
            "ip_proto": int(ip4.proto),
        }
        tcp4 = pkt.get_protocol(tcp.tcp)
        udp4 = pkt.get_protocol(udp.udp)
        if tcp4:
            fields.update(tcp_src=int(tcp4.src_port), tcp_dst=int(tcp4.dst_port))
        elif udp4:
            fields.update(udp_src=int(udp4.src_port), udp_dst=int(udp4.dst_port))
        return fields

    def _packet_out(self, msg, in_port: int, out_port: int) -> None:
        dp, ofp, parser = msg.datapath, msg.datapath.ofproto, msg.datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        ))

    # ---------------------------- routing logic ----------------------------
    def _neighbors(self, node: int) -> Iterable[int]:
        for a, b in NSFNET_LINKS:
            if a == node:
                yield b
            elif b == node:
                yield a

    def _out_port(self, u: int, v: int) -> Optional[int]:
        if (u, v) in self.link_ports:
            return int(self.link_ports[(u, v)][0])
        # EventLinkAdd is directional in normal discovery, but keep a fallback.
        for (dpid, port), neigh in self.port_to_neighbor.items():
            if dpid == u and neigh == v:
                return int(port)
        return None

    def _path_ports_ready(self, path: Sequence[int]) -> bool:
        for u, v in zip(path, path[1:]):
            p = self._out_port(u, v)
            if p is None or (u, p) in self.blocked_ports:
                return False
        return True

    def _edge_state(self, u: int, v: int) -> Dict[str, float]:
        ek = edge_key(u, v)
        delay_ms = float(NSFNET_LINKS[ek])
        util_candidates, loss_candidates = [], []
        for a, b in ((u, v), (v, u)):
            p = self._out_port(a, b)
            if p is not None:
                if (a, p) in self.port_rate_mbps:
                    util_candidates.append(self.port_rate_mbps[(a, p)] / CORE_LINK_BW_MBPS)
                if (a, p) in self.port_loss_percent:
                    loss_candidates.append(self.port_loss_percent[(a, p)] / 100.0)
        util = max(util_candidates) if util_candidates else 0.0
        loss = avg(loss_candidates) or 0.0
        contrib = self._recent_contributions(ek)
        hnorm = shannon_normalized(contrib)
        hdev = float(np.clip(abs(hnorm - self.reference_entropy), 0.0, 1.0))
        return {
            "utilization": float(np.clip(util, 0.0, 2.0)),
            "packet_loss": float(np.clip(loss, 0.0, 1.0)),
            "delay_ms": delay_ms,
            "delay_norm": delay_ms / MAX_STATIC_DELAY_MS,
            "normalized_entropy": hnorm,
            "entropy_deviation": hdev,
        }

    def _mitigation_penalty(self, u: int, v: int) -> float:
        """Fraction (0-1) of this edge's recent traffic contributed by
        sources currently flagged as attackers, weighted by how confident
        each detection was. Previously the controller only ever "mitigated"
        by (a) deleting the flow so the identical route could be
        immediately reinstalled with an unchanged cost function -- a no-op
        unless something else changed -- or (b) an opt-in hard block that
        almost never fired (see block_threshold fix above). This penalty
        makes entropy/congestion/learned routing itself actively avoid
        attacker-heavy links even when hard blocking is off.
        """
        now = time.monotonic()
        with self._metrics_lock:
            active = {
                ip: score
                for ip, (score, seen) in self.suspicious_sources.items()
                if now - seen <= self.suspicion_decay_seconds
            }
        if not active:
            return 0.0
        contrib = self._recent_contributions(edge_key(u, v))
        total = sum(contrib.values())
        if total <= 0:
            return 0.0
        weighted = sum(bytes_ * active.get(src, 0.0) for src, bytes_ in contrib.items())
        return float(np.clip(weighted / total, 0.0, 1.0))

    def _edge_cost(self, u: int, v: int, mode: str) -> float:
        state = self._edge_state(u, v)
        penalty = self._mitigation_penalty(u, v)
        if mode == "shortest":
            return 1.0
        if mode == "congestion":
            return 1.0 + 6.0 * state["utilization"] + 2.0 * state["packet_loss"] + 5.0 * penalty
        if mode == "learned" and self.learning_policy is not None:
            features = np.asarray([[
                state["utilization"],
                state["utilization"] ** 2,
                state["delay_norm"],
                state["packet_loss"],
                state["entropy_deviation"],
            ]], dtype=np.float32)
            try:
                if hasattr(self.learning_policy, "predict"):
                    return max(float(self.learning_policy.predict(features)[0]) + 10.0 * penalty, 1e-6)
                if hasattr(self.learning_policy, "predict_proba"):
                    p = float(self.learning_policy.predict_proba(features)[0, -1])
                    return 1.0 + 10.0 * p + 10.0 * penalty
            except Exception:
                self.logger.exception("Learning policy inference failed; using entropy cost")
            mode = "entropy"

        cfg = self.mitigation_cfg
        uval = float(np.clip(state["utilization"], 0.0, 1.0))
        cost = (
            float(cfg.get("base_cost", 1.0))
            + float(cfg.get("alpha", 2.0)) * uval
            + float(cfg.get("beta", 4.0)) * uval * uval
            + float(cfg.get("gamma", 1.0)) * state["delay_norm"]
            + float(cfg.get("delta", 2.0)) * state["packet_loss"]
            + float(cfg.get("eta", 3.0)) * state["entropy_deviation"]
            + float(cfg.get("zeta", 10.0)) * penalty
        )
        if uval >= float(cfg.get("utilization_threshold", 0.80)):
            cost *= 1.5
        return max(float(cost), 1e-6)

    def _best_path(self, src: int, dst: int, mode: str) -> Optional[List[int]]:
        if src == dst:
            return [src]
        pq = [(0.0, src, [src])]
        best = {src: 0.0}
        while pq:
            cost, node, path = heapq.heappop(pq)
            if node == dst:
                return path
            if cost > best.get(node, float("inf")):
                continue
            for neigh in self._neighbors(node):
                out_port = self._out_port(node, neigh)
                # Until link discovery finishes, do not invent port numbers.
                if out_port is None or (node, out_port) in self.blocked_ports:
                    continue
                new_cost = cost + self._edge_cost(node, neigh, mode)
                if new_cost < best.get(neigh, float("inf")):
                    best[neigh] = new_cost
                    heapq.heappush(pq, (new_cost, neigh, path + [neigh]))
        return None

    def _path_cost(self, path: Sequence[int], mode: str) -> float:
        return float(sum(self._edge_cost(u, v, mode) for u, v in zip(path, path[1:])))

    def _install_path(self, src_ip: str, dst_ip: str, path: Sequence[int], fields: Mapping[str, Any]) -> None:
        for idx, dpid in enumerate(path):
            dp = self.datapaths.get(int(dpid))
            if dp is None:
                continue
            if idx == len(path) - 1:
                out_port = HOST_PORT
            else:
                out_port = self._out_port(path[idx], path[idx + 1])
            if out_port is None:
                continue
            match = dp.ofproto_parser.OFPMatch(**dict(fields))
            self.add_flow(
                dp,
                100,
                match,
                [dp.ofproto_parser.OFPActionOutput(int(out_port))],
                idle_timeout=15,
            )
        self.installed_routes[(src_ip, dst_ip)] = {
            "path": list(path),
            "mode": self.routing_mode,
            "cost": self._path_cost(path, self.routing_mode),
            "match": dict(fields),
            "installed_at": time.time(),
        }

    def _delete_ip_route(self, src_ip: str, dst_ip: str) -> None:
        for dp in list(self.datapaths.values()):
            parser, ofp = dp.ofproto_parser, dp.ofproto
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
            )
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                priority=100,
                match=match,
            )
            dp.send_msg(mod)
        self.installed_routes.pop((src_ip, dst_ip), None)

    def _reroute_if_needed(self) -> None:
        for (src_ip, dst_ip), info in list(self.installed_routes.items()):
            src_sw = HOST_IP_TO_SWITCH.get(src_ip)
            dst_sw = HOST_IP_TO_SWITCH.get(dst_ip)
            if not src_sw or not dst_sw:
                continue
            new_path = self._best_path(src_sw, dst_sw, self.routing_mode)
            if not new_path:
                continue
            old_path = info["path"]
            old_cost = self._path_cost(old_path, self.routing_mode)
            new_cost = self._path_cost(new_path, self.routing_mode)
            overloaded = any(
                self._edge_state(u, v)["utilization"] >= float(self.mitigation_cfg.get("utilization_threshold", 0.8))
                for u, v in zip(old_path, old_path[1:])
            )
            improved = new_cost < old_cost * (1.0 - self.route_hysteresis)
            if new_path != old_path and (overloaded or improved):
                self._delete_ip_route(src_ip, dst_ip)

    # ------------------------- live stats collection ------------------------
    def _monitor_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                try:
                    parser, ofp = dp.ofproto_parser, dp.ofproto
                    dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))
                    dp.send_msg(parser.OFPFlowStatsRequest(dp))
                    dp.send_msg(parser.OFPPortDescStatsRequest(dp, 0))
                except Exception:
                    self.logger.exception("Stats request failed for dpid=%s", getattr(dp, "id", "?"))
            try:
                self._reroute_if_needed()
            except Exception:
                self.logger.exception("Dynamic reroute check failed")
            try:
                # Under full source-IP spoofing (e.g. hping3 --rand-source),
                # almost every packet creates a distinct (src_ip, dst_ip) key
                # in flow_origin, so this cache needs active pruning rather
                # than relying on keys naturally being reused.
                cutoff = time.monotonic() - self.flow_origin_ttl
                stale = [k for k, (_, seen) in self.flow_origin.items() if seen < cutoff]
                for k in stale:
                    self.flow_origin.pop(k, None)
                susp_cutoff = time.monotonic() - self.suspicion_decay_seconds
                with self._metrics_lock:
                    stale_susp = [k for k, (_, seen) in self.suspicious_sources.items() if seen < susp_cutoff]
                    for k in stale_susp:
                        self.suspicious_sources.pop(k, None)
            except Exception:
                self.logger.exception("flow_origin cache cleanup failed")
            hub.sleep(self.stats_interval)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        now = time.monotonic()
        dpid = int(ev.msg.datapath.id)
        ofp = ev.msg.datapath.ofproto
        for stat in ev.msg.body:
            port = int(stat.port_no)
            if port >= ofp.OFPP_MAX:
                continue
            current = (
                now,
                int(stat.tx_bytes), int(stat.rx_bytes),
                int(stat.tx_packets), int(stat.rx_packets),
                int(stat.tx_dropped), int(stat.rx_dropped),
            )
            key = (dpid, port)
            prev = self.prev_port.get(key)
            self.prev_port[key] = current
            if prev is None:
                continue
            dt = max(now - prev[0], 1e-6)
            dtxb = max(0, current[1] - prev[1])
            drxb = max(0, current[2] - prev[2])
            dtxp = max(0, current[3] - prev[3])
            drxp = max(0, current[4] - prev[4])
            ddrop = max(0, current[5] - prev[5]) + max(0, current[6] - prev[6])
            self.port_rate_mbps[key] = max(dtxb, drxb) * 8.0 / dt / 1e6
            denom = dtxp + drxp + ddrop
            self.port_loss_percent[key] = (100.0 * ddrop / denom) if denom > 0 else 0.0

    def _extract_out_port(self, stat) -> Optional[int]:
        try:
            for inst in stat.instructions:
                for action in getattr(inst, "actions", []):
                    if hasattr(action, "port"):
                        return int(action.port)
        except Exception:
            return None
        return None

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        now = time.monotonic()
        dpid = int(ev.msg.datapath.id)
        for stat in ev.msg.body:
            if int(stat.priority) < 100:
                continue
            # Ryu OFPMatch is mapping-like, but on some Ryu/Python versions
            # dict(stat.match) incorrectly falls back to integer __getitem__ access
            # and raises KeyError: 0.  Use the explicit items() API instead.
            try:
                match = dict(stat.match.items())
            except Exception:
                # Defensive fallback for older/custom Ryu OFPMatch implementations.
                match = {}
                for field in (
                    "eth_type", "ipv4_src", "ipv4_dst", "ip_proto",
                    "tcp_src", "tcp_dst", "udp_src", "udp_dst",
                    "in_port",
                ):
                    try:
                        value = stat.match.get(field)
                    except Exception:
                        try:
                            value = stat.match[field]
                        except Exception:
                            value = None
                    if value is not None:
                        match[field] = value

            src_ip, dst_ip = match.get("ipv4_src"), match.get("ipv4_dst")
            if not src_ip or not dst_ip:
                continue
            out_port = self._extract_out_port(stat)
            flow_key = (
                dpid, src_ip, dst_ip, match.get("ip_proto"),
                match.get("tcp_src"), match.get("tcp_dst"),
                match.get("udp_src"), match.get("udp_dst"), out_port,
            )
            prev = self.prev_flow.get(flow_key)
            cur_bytes, cur_pkts = int(stat.byte_count), int(stat.packet_count)
            self.prev_flow[flow_key] = (now, cur_bytes, cur_pkts)
            if prev is None:
                continue
            dt = max(now - prev[0], 1e-6)
            delta_bytes = max(0, cur_bytes - prev[1])
            delta_pkts = max(0, cur_pkts - prev[2])
            if delta_pkts <= 0 and delta_bytes <= 0:
                continue

            neigh = self.port_to_neighbor.get((dpid, out_port)) if out_port is not None else None
            if neigh is not None:
                # Key contribution by the flow's physical origin (falls back
                # to the raw src_ip only if that origin isn't cached, e.g.
                # right at controller startup). Under spoofed source IPs a
                # raw-IP key would be single-use noise; the origin switch is
                # the same real identity every time that host attacks.
                origin = self._physical_origin_switch(str(src_ip), str(dst_ip))
                identity = origin if origin is not None else str(src_ip)
                self.link_contrib[edge_key(dpid, neigh)].append((now, identity, float(delta_bytes)))

            # Native OpenFlow-stat inference. It is lower-fidelity than /ids/flow
            # because OpenFlow does not expose every training feature.
            raw = {
                "duration": dt,
                "packet_count": delta_pkts,
                "byte_count": delta_bytes,
                "l4Proto": int(match.get("ip_proto", 0) or 0),
                "srcPort": match.get("tcp_src", match.get("udp_src", 0)),
                "dstPort": match.get("tcp_dst", match.get("udp_dst", 0)),
                "ethType": "0x0800",
                "%dir": "A",
            }
            try:
                self._detect(raw, src_ip=str(src_ip), dst_ip=str(dst_ip), source="openflow_stats", activate_session=False)
            except Exception:
                self.logger.exception("Native OpenFlow detector inference failed")

    def _recent_contributions(self, ek: Tuple[int, int]) -> Dict[str, float]:
        q = self.link_contrib[ek]
        cutoff = time.monotonic() - self.entropy_window
        while q and q[0][0] < cutoff:
            q.popleft()
        out: Dict[str, float] = defaultdict(float)
        for _, src, bytes_count in q:
            out[src] += float(bytes_count)
        return dict(out)

    # ----------------------------- IDS runtime -----------------------------
    def _mark_session_active(self) -> None:
        NETWORK_METRICS_DIR.mkdir(parents=True, exist_ok=True)
        if not SESSION_ACTIVE_FLAG.exists():
            SESSION_ACTIVE_FLAG.touch()
        try:
            SESSION_STOP_FLAG.unlink()
        except FileNotFoundError:
            pass

    def _mitigate_attack(self, src_ip: Optional[str], dst_ip: Optional[str], score: float) -> str:
        if not src_ip:
            return "score_recorded"
        now = time.monotonic()
        # Same identity resolution as the link-contribution tracking above:
        # prefer the physical origin switch (stable even under spoofed
        # src_ip) and only fall back to the raw IP if origin isn't known yet.
        origin = self._physical_origin_switch(src_ip, dst_ip)
        suspect_key = origin if origin is not None else src_ip
        with self._metrics_lock:
            prev_score, _ = self.suspicious_sources.get(suspect_key, (0.0, 0.0))
            self.suspicious_sources[suspect_key] = (max(score, prev_score), now)
        if src_ip and dst_ip:
            self._delete_ip_route(src_ip, dst_ip)
        if self.block_attacks and score >= self.block_threshold:
            # Resolve the switch to block at. Prefer the flow's true physical
            # ingress point (works even when ipv4_src is spoofed, e.g.
            # hping3 --rand-source, where "src_ip in HOST_IP_TO_SWITCH" would
            # almost never be true and this branch would silently never
            # fire). Fall back to the static IP map for non-spoofed traffic.
            dpid = origin if origin is not None else HOST_IP_TO_SWITCH.get(src_ip)
            dp = self.datapaths.get(dpid) if dpid is not None else None
            if dp is not None:
                parser = dp.ofproto_parser
                # Match on the ingress host port, not on ipv4_src: filtering
                # by claimed source IP is a no-op against spoofed traffic,
                # since every packet can carry a different forged address.
                # Blocking the physical port drops the attacker's traffic
                # regardless of what IP header it fabricates.
                match = parser.OFPMatch(in_port=HOST_PORT)
                self.add_flow(
                    dp,
                    300,
                    match,
                    [],
                    hard_timeout=self.block_seconds,
                    cookie=0x424C4F43,
                )
                return f"temporary_block_{self.block_seconds}s"
        return f"{self.routing_mode}_reroute"

    def _physical_origin_switch(self, src_ip: Optional[str], dst_ip: Optional[str]) -> Optional[int]:
        """The true ingress switch for this (src_ip, dst_ip) flow, from the
        packet_in cache -- not from the IP header, which can be spoofed."""
        if not src_ip or not dst_ip:
            return None
        entry = self.flow_origin.get((src_ip, dst_ip))
        if entry is None:
            return None
        dpid, seen = entry
        if time.monotonic() - seen > self.flow_origin_ttl:
            return None
        return dpid

    def _resolve_label_override(self, ip: Optional[str]) -> Optional[int]:
        if not ip:
            return None
        now = time.monotonic()
        with self._metrics_lock:
            entry = self.label_overrides.get(ip)
            if entry is None:
                return None
            role, expiry = entry
            if now > expiry:
                del self.label_overrides[ip]
                return None
            return role

    def set_label_override(self, ip: str, role: Any, duration_seconds: Optional[float]) -> Dict[str, Any]:
        if not ip:
            raise ValueError("ip is required")
        role_int = self._normalize_ground_truth(role)
        if role_int is None:
            raise ValueError("role must be one of: attack/1, normal/0")
        if duration_seconds is None:
            expiry = float("inf")
        else:
            duration_seconds = float(duration_seconds)
            if duration_seconds <= 0:
                raise ValueError("duration_seconds must be positive")
            expiry = time.monotonic() + duration_seconds
        with self._metrics_lock:
            self.label_overrides[ip] = (role_int, expiry)
        self.logger.info(
            "Ground-truth override set: %s -> %s for %s",
            ip, "attack" if role_int == 1 else "normal",
            "no expiry" if duration_seconds is None else f"{duration_seconds:.0f}s",
        )
        return {
            "ip": ip,
            "role": "attack" if role_int == 1 else "normal",
            "duration_seconds": duration_seconds,
        }

    def clear_label_override(self, ip: str) -> Dict[str, Any]:
        if not ip:
            raise ValueError("ip is required")
        with self._metrics_lock:
            existed = self.label_overrides.pop(ip, None) is not None
        return {"ip": ip, "cleared": existed}

    def list_label_overrides(self) -> Dict[str, Any]:
        now = time.monotonic()
        with self._metrics_lock:
            expired = [ip for ip, (_, expiry) in self.label_overrides.items() if now > expiry]
            for ip in expired:
                del self.label_overrides[ip]
            active = {
                ip: {
                    "role": "attack" if role == 1 else "normal",
                    "expires_in_seconds": None if expiry == float("inf") else round(expiry - now, 1),
                }
                for ip, (role, expiry) in self.label_overrides.items()
            }
        return {"overrides": active}

    def _auto_ground_truth(self, src_ip: Optional[str], dst_ip: Optional[str]) -> Optional[int]:
        """Same convention as tranalyzer_watcher.py's --label-by-ip, applied
        inside the controller itself so native OpenFlow-stat detections (and
        any REST call that omits ground_truth) still get scored, instead of
        requiring the external watcher to be running with that flag."""
        if not self.auto_label_by_ip:
            return None
        # A dynamic override (see /ids/label_override) always wins over the
        # static convention below, so you can test "attack from a normally
        # trusted host" without touching SDN_ATTACK_IPS or restarting Ryu.
        override = self._resolve_label_override(src_ip)
        if override is None:
            override = self._resolve_label_override(dst_ip)
        if override is not None:
            return override
        endpoints = {ip for ip in (src_ip, dst_ip) if ip}
        if endpoints & self.auto_label_attack_ips:
            return 1
        if endpoints & self.auto_label_normal_ips:
            return 0
        # Neither address matches a known host IP directly -- most likely the
        # source IP is spoofed. Fall back to where the flow's first packet
        # physically entered the network, which spoofing cannot hide.
        origin_dpid = self._physical_origin_switch(src_ip, dst_ip)
        if origin_dpid is not None:
            return self.auto_label_switch_roles.get(origin_dpid)
        return None

    @staticmethod
    def _normalize_ground_truth(value: Any) -> Optional[int]:
        if value is None or value == "":
            return None
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, np.integer)):
            if int(value) in (0, 1):
                return int(value)
        if isinstance(value, float) and value in (0.0, 1.0):
            return int(value)
        text = str(value).strip().lower()
        if text in {"0", "normal", "benign", "legitimate"}:
            return 0
        if text in {"1", "attack", "malicious", "anomaly", "anomalous"}:
            return 1
        raise ValueError(f"ground_truth must be 0/1 or normal/attack, got: {value!r}")

    def _record_labeled_prediction(
        self,
        ground_truth: Optional[int],
        prediction: int,
        score: float,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        source: str,
    ) -> None:
        if ground_truth is None:
            return
        y = int(ground_truth)
        p = int(prediction)
        with self._metrics_lock:
            self.eval_true.append(y)
            self.eval_pred.append(p)
            self.eval_score.append(float(score))
            if y == 0 and p == 0:
                self.eval_tn += 1
            elif y == 0 and p == 1:
                self.eval_fp += 1
            elif y == 1 and p == 0:
                self.eval_fn += 1
            elif y == 1 and p == 1:
                self.eval_tp += 1

            write_header = (not EVAL_PREDICTIONS_CSV.exists()) or EVAL_PREDICTIONS_CSV.stat().st_size == 0
            with open(EVAL_PREDICTIONS_CSV, "a", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=[
                    "timestamp_utc", "source", "src_ip", "dst_ip",
                    "ground_truth", "prediction", "attack_probability", "correct",
                ])
                if write_header:
                    writer.writeheader()
                writer.writerow({
                    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "source": source, "src_ip": src_ip, "dst_ip": dst_ip,
                    "ground_truth": y, "prediction": p,
                    "attack_probability": float(score), "correct": int(y == p),
                })

    @staticmethod
    def _binary_roc(y_true: Sequence[int], y_score: Sequence[float]) -> Dict[str, Any]:
        if len(y_true) < 2:
            return {"roc_auc": None, "fpr": [], "tpr": [], "thresholds": []}
        y = np.asarray(y_true, dtype=np.int64)
        score = np.asarray(y_score, dtype=np.float64)
        positives = int(np.sum(y == 1))
        negatives = int(np.sum(y == 0))
        if positives == 0 or negatives == 0:
            return {"roc_auc": None, "fpr": [], "tpr": [], "thresholds": []}
        order = np.argsort(-score, kind="mergesort")
        y = y[order]
        score = score[order]
        distinct = np.where(np.diff(score))[0]
        threshold_idx = np.r_[distinct, y.size - 1]
        tps = np.cumsum(y == 1)[threshold_idx].astype(float)
        fps = (1 + threshold_idx - tps).astype(float)
        tpr = np.r_[0.0, tps / positives]
        fpr = np.r_[0.0, fps / negatives]
        thresholds = [None] + score[threshold_idx].tolist()
        auc = float(np.trapz(tpr, fpr))
        return {
            "roc_auc": auc,
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "thresholds": thresholds,
        }

    def _refresh_roc_cache(self, force: bool = False) -> Dict[str, Any]:
        now = time.monotonic()
        n = len(self.eval_true)
        if (not force and self._roc_cache_n == n and self._roc_cache_time > 0):
            return self._roc_cache
        if (not force and self._roc_cache_time > 0 and now - self._roc_cache_time < 5.0):
            return self._roc_cache
        self._roc_cache = self._binary_roc(self.eval_true, self.eval_score)
        self._roc_cache_n = n
        self._roc_cache_time = now
        return self._roc_cache

    def evaluation_snapshot(self, include_curve: bool = False, force_roc: bool = False) -> Dict[str, Any]:
        with self._metrics_lock:
            tn, fp, fn, tp = self.eval_tn, self.eval_fp, self.eval_fn, self.eval_tp
            n = tn + fp + fn + tp
            accuracy = (tp + tn) / n if n else None
            precision = tp / (tp + fp) if (tp + fp) else None
            recall = tp / (tp + fn) if (tp + fn) else None
            f1 = (2 * precision * recall / (precision + recall)) if (precision is not None and recall is not None and (precision + recall) > 0) else None
            roc = self._refresh_roc_cache(force=force_roc)
            out = {
                "labeled_flows": n,
                "accuracy": accuracy,
                "accuracy_percent": None if accuracy is None else 100.0 * accuracy,
                "precision": precision,
                "precision_percent": None if precision is None else 100.0 * precision,
                "recall": recall,
                "recall_percent": None if recall is None else 100.0 * recall,
                "f1_score": f1,
                "f1_score_percent": None if f1 is None else 100.0 * f1,
                "roc_auc": roc.get("roc_auc"),
                "confusion_matrix": [[tn, fp], [fn, tp]],
                "tn": tn, "fp": fp, "fn": fn, "tp": tp,
                "definition": "confusion_matrix=[[TN,FP],[FN,TP]]; metrics require ground_truth labels",
            }
            if include_curve:
                out["roc_curve"] = {
                    "fpr": roc.get("fpr", []),
                    "tpr": roc.get("tpr", []),
                    "thresholds": roc.get("thresholds", []),
                }
            return out

    def write_evaluation_files(self) -> Dict[str, Any]:
        ev = self.evaluation_snapshot(include_curve=True, force_roc=True)
        tmp = str(EVAL_JSON) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(ev, fh, indent=2, allow_nan=False)
        os.replace(tmp, EVAL_JSON)
        with open(EVAL_CONFUSION_CSV, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["actual/predicted", "NORMAL_0", "ATTACK_1"])
            w.writerow(["NORMAL_0", ev["tn"], ev["fp"]])
            w.writerow(["ATTACK_1", ev["fn"], ev["tp"]])
        roc = ev.get("roc_curve", {})
        with open(EVAL_ROC_CSV, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["fpr", "tpr", "threshold"])
            w.writeheader()
            for fpr, tpr, thr in zip(roc.get("fpr", []), roc.get("tpr", []), roc.get("thresholds", [])):
                w.writerow({"fpr": fpr, "tpr": tpr, "threshold": thr})
        return ev

    def reset_evaluation(self) -> Dict[str, Any]:
        with self._metrics_lock:
            self.eval_true.clear(); self.eval_score.clear(); self.eval_pred.clear()
            self.eval_tn = self.eval_fp = self.eval_fn = self.eval_tp = 0
            self._roc_cache = {"roc_auc": None, "fpr": [], "tpr": [], "thresholds": []}
            self._roc_cache_n = 0
            self._roc_cache_time = 0.0
        for p in (EVAL_JSON, EVAL_PREDICTIONS_CSV, EVAL_CONFUSION_CSV, EVAL_ROC_CSV):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        return {"status": "reset", "evaluation": self.evaluation_snapshot()}

    def _detect(
        self,
        features: Mapping[str, Any],
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        source: str = "rest",
        activate_session: bool = False,
        ground_truth: Optional[int] = None,
    ) -> Dict[str, Any]:
        if activate_session:
            self._mark_session_active()
        if ground_truth is None:
            ground_truth = self._auto_ground_truth(src_ip, dst_ip)
        processing_start = time.perf_counter_ns()
        result = self.detector.predict_raw(features)
        inference_ms = float(result["inference_time_ms"])
        prob = float(result["probabilities"][0])
        label = int(result["labels"][0])
        action = "none"
        if label == 1:
            action = self._mitigate_attack(src_ip, dst_ip, prob)
        processing_ms = (time.perf_counter_ns() - processing_start) / 1e6
        response_s = processing_ms / 1000.0
        overhead_ms = max(0.0, processing_ms - inference_ms)
        self._record_labeled_prediction(ground_truth, label, prob, src_ip, dst_ip, source)

        with self._metrics_lock:
            ewma_append(self.metric_series["inference_time_ms"], inference_ms)
            ewma_append(self.metric_series["processing_time_ms"], processing_ms)
            ewma_append(self.metric_series["response_time_s"], response_s)
            ewma_append(self.metric_series["controller_overhead_ms"], overhead_ms)
            self.detection_count += 1
            if label == 1:
                self.attack_count += 1
            self.last_detection = {
                "timestamp": time.time(),
                "source": source,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "attack_probability": prob,
                "prediction": "ATTACK" if label else "NORMAL",
                "ground_truth": ground_truth,
                "mitigation_action": action,
            }
        return {
            "prediction": "ATTACK" if label else "NORMAL",
            "label": label,
            "attack_probability": prob,
            "threshold": self.detector.threshold,
            "ground_truth": ground_truth,
            "mitigation_action": action,
            "inference_time_ms": inference_ms,
            "preprocessing_time_ms": float(result.get("preprocessing_time_ms", 0.0)),
            "processing_time_ms": processing_ms,
            "response_time_s": response_s,
            "controller_overhead_ms": overhead_ms,
        }

    def detect_rest_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        src_ip = payload.get("src_ip", payload.get("srcIP"))
        dst_ip = payload.get("dst_ip", payload.get("dstIP"))
        # A dynamic override (set via /ids/label_override) always wins, even
        # over an explicit ground_truth supplied in the payload. Without this,
        # tranalyzer_watcher.py --label-by-ip would keep sending its own
        # explicit label from the SAME static h1-h3/h4-h6 convention the
        # override exists to intentionally contradict for a test, silently
        # cancelling the override out.
        ground_truth = self._resolve_label_override(src_ip)
        if ground_truth is None:
            ground_truth = self._resolve_label_override(dst_ip)
        if ground_truth is None:
            ground_truth = self._normalize_ground_truth(payload.get("ground_truth", payload.get("true_label")))
        if ground_truth is None:
            ground_truth = self._auto_ground_truth(src_ip, dst_ip)
        if "vector" in payload:
            self._mark_session_active()
            start = time.perf_counter_ns()
            result = self.detector.predict_vector(payload["vector"])
            inference_ms = float(result["inference_time_ms"])
            prob = float(result["probabilities"][0])
            label = int(result["labels"][0])
            action = self._mitigate_attack(src_ip, dst_ip, prob) if label else "none"
            processing_ms = (time.perf_counter_ns() - start) / 1e6
            response_s = processing_ms / 1000.0
            overhead_ms = max(0.0, processing_ms - inference_ms)
            self._record_labeled_prediction(ground_truth, label, prob, src_ip, dst_ip, "rest_vector")
            with self._metrics_lock:
                ewma_append(self.metric_series["inference_time_ms"], inference_ms)
                ewma_append(self.metric_series["processing_time_ms"], processing_ms)
                ewma_append(self.metric_series["response_time_s"], response_s)
                ewma_append(self.metric_series["controller_overhead_ms"], overhead_ms)
                self.detection_count += 1
                self.attack_count += int(label == 1)
            return {
                "prediction": "ATTACK" if label else "NORMAL",
                "label": label,
                "attack_probability": prob,
                "threshold": self.detector.threshold,
                "ground_truth": ground_truth,
                "mitigation_action": action,
                "inference_time_ms": inference_ms,
                "processing_time_ms": processing_ms,
                "response_time_s": response_s,
                "controller_overhead_ms": overhead_ms,
            }
        features = payload.get("features", payload)
        if not isinstance(features, Mapping):
            raise ValueError("POST /ids/flow expects JSON object or {'features': {...}}")
        return self._detect(
            features, src_ip, dst_ip, source="rest", activate_session=True,
            ground_truth=ground_truth,
        )

    def run_evasion_simulation(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Legacy-compatible labeled/evasion evaluation.

        Accepts both the old keys used in READMEFULL (n_flows, split,
        evasion_strength) and the newer max_attack_samples alias.  The response
        includes a `results` list so the user's previous JSON->CSV command keeps
        working unchanged.
        """
        SESSION_STOP_FLAG.touch()

        split = str(payload.get("split", "test")).strip().lower()
        if split not in {"train", "val", "test"}:
            raise ValueError("split must be train, val, or test")
        dataset_path = self.test_npz.parent / f"{split}.npz"
        if not dataset_path.exists():
            dataset_path = self.test_npz
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {dataset_path}")

        n_flows = int(payload.get("n_flows", payload.get("max_attack_samples", 2000)))
        n_flows = max(1, min(n_flows, 100000))
        strength = float(np.clip(float(payload.get("evasion_strength", 0.15)), 0.0, 1.0))
        seed = int(payload.get("seed", 42))

        data = np.load(str(dataset_path))
        x = data["X"].astype(np.float32, copy=False)
        y = data["y"].astype(np.int64, copy=False)
        if len(x) == 0:
            raise ValueError(f"Dataset {dataset_path} is empty")

        rng = np.random.default_rng(seed)
        take = min(n_flows, len(x))
        indices = rng.choice(len(x), size=take, replace=False) if take < len(x) else np.arange(len(x))
        xs = x[indices].copy()
        ys = y[indices].copy()

        normal_idx_all = np.flatnonzero(y == 0)
        if len(normal_idx_all) == 0:
            raise ValueError("No normal-class samples are available for the evasion reference centroid")
        normal_centroid = x[normal_idx_all].mean(axis=0)
        numeric_idx = np.asarray(
            [i for i, name in enumerate(self.detector.feature_columns) if name.startswith("num__")],
            dtype=np.int64,
        )

        xadv = xs.copy()
        attack_mask = ys == 1
        if np.any(attack_mask):
            xa = xadv[attack_mask]
            xa[:, numeric_idx] = (
                (1.0 - strength) * xa[:, numeric_idx]
                + strength * normal_centroid[numeric_idx]
            )
            xadv[attack_mask] = xa

        t0 = time.perf_counter()
        baseline_prob = self.detector.predict_probabilities(xs)
        evasion_prob = self.detector.predict_probabilities(xadv)
        baseline_pred = (baseline_prob >= self.detector.threshold).astype(np.int64)
        evasion_pred = (evasion_prob >= self.detector.threshold).astype(np.int64)

        attack_truth = ys == 1
        if np.any(attack_truth):
            baseline_recall = float(np.mean(baseline_pred[attack_truth] == 1))
            evasion_recall = float(np.mean(evasion_pred[attack_truth] == 1))
        else:
            baseline_recall = 0.0
            evasion_recall = 0.0
        if baseline_recall > 0:
            retention = 100.0 * evasion_recall / baseline_recall
            degradation = 100.0 * max(0.0, baseline_recall - evasion_recall) / baseline_recall
        else:
            retention = 0.0
            degradation = 0.0

        baseline_accuracy = 100.0 * float(np.mean(baseline_pred == ys))
        evasion_accuracy = 100.0 * float(np.mean(evasion_pred == ys))
        elapsed = time.perf_counter() - t0

        results = []
        for idx, truth, bp, bpred, ep, epred in zip(
            indices.tolist(), ys.tolist(), baseline_prob.tolist(), baseline_pred.tolist(),
            evasion_prob.tolist(), evasion_pred.tolist()
        ):
            results.append({
                "sample_index": int(idx),
                "split": split,
                "true_label": int(truth),
                "baseline_probability": float(bp),
                "baseline_prediction": int(bpred),
                "evasion_probability": float(ep),
                "evasion_prediction": int(epred),
                "evasion_strength": strength,
                "baseline_correct": int(int(bpred) == int(truth)),
                "evasion_correct": int(int(epred) == int(truth)),
            })

        summary = {
            "n_flows": int(take),
            "split": split,
            "evasion_strength": strength,
            "baseline_accuracy_percent": baseline_accuracy,
            "evasion_accuracy_percent": evasion_accuracy,
            "baseline_attack_recall_percent": 100.0 * baseline_recall,
            "evasion_attack_recall_percent": 100.0 * evasion_recall,
            "evasion_degradation_percentage": degradation,
            "robustness_retention_percent": retention,
            "simulation_time_s": elapsed,
        }
        with self._metrics_lock:
            self.evasion_degradation_percentage = float(degradation)
            self.robustness_retention_percent = float(retention)

        return {
            **summary,
            "summary": summary,
            "results": results,
            "definition": (
                "Attack rows are perturbed in transformed numeric feature space toward "
                "the normal-class centroid; normal rows are left unchanged."
            ),
        }

    # --------------------------- metrics + REST ----------------------------
    def _read_network_metrics(self) -> Dict[str, Any]:
        try:
            with open(NETWORK_METRICS_PATH, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _core_utilization(self) -> Tuple[Optional[float], Optional[float]]:
        values = []
        for u, v in NSFNET_LINKS:
            state = self._edge_state(u, v)
            values.append(100.0 * state["utilization"])
        if not values:
            return None, None
        return max(values), float(sum(values) / len(values))

    def metrics_snapshot(self) -> Dict[str, Any]:
        net = self._read_network_metrics()
        max_util, mean_util = self._core_utilization()
        throughput_bps = net.get("network_throughput_bps")
        throughput_mbps = (float(throughput_bps) / 1e6) if throughput_bps is not None else None
        ev = self.evaluation_snapshot(include_curve=False, force_roc=False)
        with self._metrics_lock:
            snapshot = {
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "routing_mode": self.routing_mode,
                "inference_time_ms": safe_round(avg(self.metric_series["inference_time_ms"]), 6),
                "processing_time_ms": safe_round(avg(self.metric_series["processing_time_ms"]), 6),
                "response_time_s": safe_round(avg(self.metric_series["response_time_s"]), 9),
                "network_throughput_mbps": safe_round(throughput_mbps, 6),
                "packet_loss_percent": safe_round(net.get("packet_loss_percent"), 6),
                "jitter_ms": safe_round(net.get("jitter_ms"), 6),
                "latency_ms": safe_round(net.get("latency_ms"), 6),
                "cpu_percent": safe_round(self.process.cpu_percent(None), 3),
                "memory_mb": safe_round(self.process.memory_info().rss / (1024.0 * 1024.0), 3),
                "core_link_utilization_percent": safe_round(max_util, 6),
                "mean_core_link_utilization_percent": safe_round(mean_util, 6),
                "evasion_degradation_percentage": safe_round(self.evasion_degradation_percentage, 6),
                "robustness_retention_percent": safe_round(self.robustness_retention_percent, 6),
                "controller_overhead_ms": safe_round(avg(self.metric_series["controller_overhead_ms"]), 6),
                "labeled_flows": int(ev["labeled_flows"]),
                "accuracy_percent": safe_round(ev["accuracy_percent"], 6),
                "precision_percent": safe_round(ev["precision_percent"], 6),
                "recall_percent": safe_round(ev["recall_percent"], 6),
                "f1_score_percent": safe_round(ev["f1_score_percent"], 6),
                "roc_auc": safe_round(ev["roc_auc"], 9),
                "tn": int(ev["tn"]), "fp": int(ev["fp"]),
                "fn": int(ev["fn"]), "tp": int(ev["tp"]),
                "confusion_matrix": ev["confusion_matrix"],
                "detection_count": int(self.detection_count),
                "attack_count": int(self.attack_count),
                "last_detection": dict(self.last_detection),
                "network_measurement_status": net.get("status"),
                "uptime_s": safe_round(time.time() - self.start_time, 3),
            }
        return snapshot

    def _live_metrics_loop(self):
        fields = [
            "timestamp_utc", "routing_mode", "inference_time_ms", "processing_time_ms",
            "response_time_s", "network_throughput_mbps", "packet_loss_percent",
            "jitter_ms", "latency_ms", "cpu_percent", "memory_mb",
            "core_link_utilization_percent", "mean_core_link_utilization_percent",
            "evasion_degradation_percentage", "robustness_retention_percent",
            "controller_overhead_ms", "labeled_flows", "accuracy_percent",
            "precision_percent", "recall_percent", "f1_score_percent", "roc_auc",
            "tn", "fp", "fn", "tp", "detection_count", "attack_count",
        ]
        header_written = False
        if RYU_METRICS_CSV.exists() and RYU_METRICS_CSV.stat().st_size > 0:
            try:
                with open(RYU_METRICS_CSV, newline="", encoding="utf-8") as fh:
                    existing_header = next(csv.reader(fh), [])
                if existing_header == fields:
                    header_written = True
                else:
                    backup = RYU_METRICS_CSV.with_name("ryu_live_metrics_previous_schema.csv")
                    try:
                        backup.unlink()
                    except FileNotFoundError:
                        pass
                    os.replace(RYU_METRICS_CSV, backup)
                    self.logger.info("Rotated old metrics CSV schema to %s", backup)
            except Exception:
                self.logger.exception("Could not inspect old live metrics CSV; starting a fresh one")
                try:
                    RYU_METRICS_CSV.unlink()
                except OSError:
                    pass

        while True:
            try:
                m = self.metrics_snapshot()
                tmp = str(RYU_METRICS_JSON) + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(m, fh, indent=2)
                os.replace(tmp, RYU_METRICS_JSON)

                with open(RYU_METRICS_CSV, "a", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
                    if not header_written:
                        writer.writeheader()
                        header_written = True
                    writer.writerow(m)

                def f(v, unit=""):
                    return "N/A" if v is None else f"{v:.3f}{unit}"
                self.logger.info(
                    "LIVE | infer=%s | proc=%s | response=%s | throughput=%s | loss=%s | "
                    "jitter=%s | latency=%s | CPU=%s | mem=%s | core-util=%s | "
                    "acc=%s | prec=%s | recall=%s | f1=%s | auc=%s | CM=[[TN:%d,FP:%d],[FN:%d,TP:%d]] | "
                    "evasion-deg=%s | robustness=%s | ctrl-overhead=%s",
                    f(m["inference_time_ms"], "ms"),
                    f(m["processing_time_ms"], "ms"),
                    f(m["response_time_s"], "s"),
                    f(m["network_throughput_mbps"], "Mbps"),
                    f(m["packet_loss_percent"], "%"),
                    f(m["jitter_ms"], "ms"),
                    f(m["latency_ms"], "ms"),
                    f(m["cpu_percent"], "%"),
                    f(m["memory_mb"], "MB"),
                    f(m["core_link_utilization_percent"], "%"),
                    f(m["accuracy_percent"], "%"),
                    f(m["precision_percent"], "%"),
                    f(m["recall_percent"], "%"),
                    f(m["f1_score_percent"], "%"),
                    f(m["roc_auc"]),
                    int(m["tn"]), int(m["fp"]), int(m["fn"]), int(m["tp"]),
                    f(m["evasion_degradation_percentage"], "%"),
                    f(m["robustness_retention_percent"], "%"),
                    f(m["controller_overhead_ms"], "ms"),
                )
            except Exception:
                self.logger.exception("Live metrics update failed")
            hub.sleep(1.0)

    def set_routing_mode(self, mode: str) -> Dict[str, Any]:
        mode = str(mode).lower().strip()
        if mode not in {"entropy", "shortest", "congestion", "learned"}:
            raise ValueError("mode must be entropy, shortest, congestion, or learned")
        if mode == "learned" and self.learning_policy is None:
            raise ValueError("learned mode needs SDN_LEARNING_POLICY pointing to a fitted pickle model")
        self.routing_mode = mode
        for src_ip, dst_ip in list(self.installed_routes):
            self._delete_ip_route(src_ip, dst_ip)
        return {"routing_mode": self.routing_mode}

    def compare_routes(self, src_ip: str, dst_ip: str) -> Dict[str, Any]:
        src, dst = HOST_IP_TO_SWITCH.get(src_ip), HOST_IP_TO_SWITCH.get(dst_ip)
        if not src or not dst:
            raise ValueError("src_ip and dst_ip must be one of 10.0.0.1 ... 10.0.0.13")
        modes = ["shortest", "congestion", "entropy"]
        if self.learning_policy is not None:
            modes.append("learned")
        out = {}
        for mode in modes:
            p = self._best_path(src, dst, mode)
            if not p:
                out[mode] = {"available": False, "reason": "link discovery/RSTP has no usable path yet"}
                continue
            states = [self._edge_state(u, v) for u, v in zip(p, p[1:])]
            out[mode] = {
                "available": True,
                "switch_path": [f"s{x}" for x in p],
                "path_cost": self._path_cost(p, mode),
                "bottleneck_utilization_percent": 100.0 * max((s["utilization"] for s in states), default=0.0),
                "mean_link_loss_percent": 100.0 * (avg([s["packet_loss"] for s in states]) or 0.0),
                "static_path_delay_ms": sum(s["delay_ms"] for s in states),
                "mean_normalized_entropy": avg([s["normalized_entropy"] for s in states]) or 0.0,
            }
        if self.learning_policy is None:
            out["learned"] = {
                "available": False,
                "reason": "No trained learning-based routing policy was supplied in the uploaded artifacts. Set SDN_LEARNING_POLICY to evaluate one.",
            }
        return {"src_ip": src_ip, "dst_ip": dst_ip, "routes": out}


class NSFNetRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app: NSFNetSDCGANController = data[APP_INSTANCE]

    @staticmethod
    def _json_response(payload: Mapping[str, Any], status: int = 200) -> Response:
        return Response(
            status=status,
            content_type="application/json",
            body=json.dumps(payload, indent=2, default=str).encode("utf-8"),
        )

    @staticmethod
    def _body(req) -> Dict[str, Any]:
        if not req.body:
            return {}
        try:
            return json.loads(req.body.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Invalid JSON body: {exc}")

    @route("ids_status", "/ids/status", methods=["GET"])
    def status(self, req, **kwargs):
        try:
            metrics = self.app.metrics_snapshot()
            return self._json_response({
                "status": "running",
                "model": self.app.detector.bundle.get("model_type"),
                "input_dim": self.app.detector.input_dim,
                "threshold": self.app.detector.threshold,
                "routing_mode": self.app.routing_mode,
                "datapaths": sorted(self.app.datapaths),
                "flows_processed": self.app.detection_count,
                "attacks_detected": self.app.attack_count,
                "last_detection": self.app.last_detection,
                "mitigation": {
                    "block_attacks": self.app.block_attacks,
                    "block_threshold": self.app.block_threshold,
                    "block_seconds": self.app.block_seconds,
                    "suspicion_decay_seconds": self.app.suspicion_decay_seconds,
                    "currently_suspicious_sources": sorted(str(k) for k in self.app.suspicious_sources),
                },
                "auto_ground_truth_labeling": {
                    "enabled": self.app.auto_label_by_ip,
                    "attack_ips": sorted(self.app.auto_label_attack_ips),
                    "normal_ips": sorted(self.app.auto_label_normal_ips),
                    "active_overrides": self.app.list_label_overrides()["overrides"],
                },
                "metrics": metrics,
            })
        except Exception as exc:
            self.app.logger.exception("/ids/status failed")
            return self._json_response({"error": str(exc)}, status=500)

    @route("ids_health", "/ids/health", methods=["GET"])
    def health(self, req, **kwargs):
        return self._json_response({
            "status": "ok",
            "model": self.app.detector.bundle.get("model_type"),
            "input_dim": self.app.detector.input_dim,
            "threshold": self.app.detector.threshold,
            "routing_mode": self.app.routing_mode,
            "datapaths": sorted(self.app.datapaths),
        })

    @route("ids_metrics", "/ids/metrics", methods=["GET"])
    def metrics(self, req, **kwargs):
        try:
            return self._json_response(self.app.metrics_snapshot())
        except Exception as exc:
            self.app.logger.exception("/ids/metrics failed")
            return self._json_response({"error": str(exc)}, status=500)

    @route("ids_flow", "/ids/flow", methods=["POST"])
    def ids_flow(self, req, **kwargs):
        try:
            result = self.app.detect_rest_payload(self._body(req))
            return self._json_response(result)
        except Exception as exc:
            self.app.logger.exception("/ids/flow failed")
            return self._json_response({"error": str(exc)}, status=400)

    @route("ids_evaluation", "/ids/evaluation", methods=["GET"])
    def ids_evaluation(self, req, **kwargs):
        try:
            return self._json_response(self.app.write_evaluation_files())
        except Exception as exc:
            self.app.logger.exception("/ids/evaluation failed")
            return self._json_response({"error": str(exc)}, status=400)

    @route("ids_evaluation_reset", "/ids/evaluation/reset", methods=["POST"])
    def ids_evaluation_reset(self, req, **kwargs):
        try:
            return self._json_response(self.app.reset_evaluation())
        except Exception as exc:
            self.app.logger.exception("/ids/evaluation/reset failed")
            return self._json_response({"error": str(exc)}, status=400)

    @route("ids_simulate", "/ids/simulate", methods=["POST"])
    def ids_simulate(self, req, **kwargs):
        try:
            return self._json_response(self.app.run_evasion_simulation(self._body(req)))
        except Exception as exc:
            self.app.logger.exception("/ids/simulate failed")
            return self._json_response({"error": str(exc)}, status=400)

    @route("routing_mode", "/routing/mode", methods=["POST"])
    def routing_mode(self, req, **kwargs):
        try:
            body = self._body(req)
            return self._json_response(self.app.set_routing_mode(body.get("mode", "")))
        except Exception as exc:
            return self._json_response({"error": str(exc)}, status=400)

    @route("routing_compare", "/routing/compare", methods=["GET"])
    def routing_compare(self, req, **kwargs):
        try:
            src = req.params.get("src_ip", "10.0.0.4")
            dst = req.params.get("dst_ip", "10.0.0.12")
            return self._json_response(self.app.compare_routes(src, dst))
        except Exception as exc:
            return self._json_response({"error": str(exc)}, status=400)

    @route("ids_label_override_list", "/ids/label_override", methods=["GET"])
    def ids_label_override_list(self, req, **kwargs):
        try:
            return self._json_response(self.app.list_label_overrides())
        except Exception as exc:
            return self._json_response({"error": str(exc)}, status=400)

    @route("ids_label_override_set", "/ids/label_override", methods=["POST"])
    def ids_label_override_set(self, req, **kwargs):
        try:
            body = self._body(req)
            result = self.app.set_label_override(
                body.get("ip"), body.get("role"), body.get("duration_seconds"),
            )
            return self._json_response(result)
        except Exception as exc:
            return self._json_response({"error": str(exc)}, status=400)

    @route("ids_label_override_clear", "/ids/label_override", methods=["DELETE"])
    def ids_label_override_clear(self, req, **kwargs):
        try:
            ip = req.params.get("ip")
            return self._json_response(self.app.clear_label_override(ip))
        except Exception as exc:
            return self._json_response({"error": str(exc)}, status=400)
