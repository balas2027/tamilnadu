"""
Real-Time Correlation Attack Engine.

Captures live network traffic and performs real-time
Entry-Exit correlation attacks to de-anonymize TOR traffic.

Features:
- Live packet capture from network interface
- Real-time Entry Guard detection
- Streaming correlation analysis
- Live attack result updates
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Tuple
from collections import deque, defaultdict
import statistics


@dataclass
class LivePacket:
    """A captured live packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    size: int
    protocol: str
    direction: int = 1  # 1=outgoing, -1=incoming


@dataclass
class LiveFlow:
    """A live network flow being tracked."""
    flow_id: str
    src_ip: str
    dst_ip: str
    packets: List[LivePacket] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    total_bytes: int = 0
    is_tor: bool = False
    tor_role: str = ""  # "Entry Guard", "Exit Node", "Relay"
    relay_nickname: str = ""
    
    def add_packet(self, pkt: LivePacket):
        """Add a packet to this flow."""
        self.packets.append(pkt)
        if not self.first_seen:
            self.first_seen = pkt.timestamp
        self.last_seen = pkt.timestamp
        self.total_bytes += pkt.size
    
    def get_iat_sequence(self) -> List[float]:
        """Get Inter-Arrival Time sequence."""
        if len(self.packets) < 2:
            return []
        
        iats = []
        for i in range(1, len(self.packets)):
            iat = self.packets[i].timestamp - self.packets[i-1].timestamp
            if iat > 0:
                iats.append(iat)
        return iats
    
    def to_dict(self) -> Dict:
        return {
            'flow_id': self.flow_id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'packets': len(self.packets),
            'bytes': self.total_bytes,
            'duration': round(self.last_seen - self.first_seen, 2),
            'is_tor': self.is_tor,
            'tor_role': self.tor_role,
            'relay_nickname': self.relay_nickname
        }


@dataclass
class RealTimeCorrelation:
    """Real-time correlation result."""
    timestamp: float
    entry_flow: str
    correlation_score: float
    timing_score: float
    volume_score: float
    is_match: bool
    entry_guard_ip: str
    entry_guard_nickname: str
    local_origin_ip: str
    evidence: List[str]
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'time_formatted': time.strftime('%H:%M:%S', time.localtime(self.timestamp)),
            'entry_flow': self.entry_flow,
            'correlation_score': round(self.correlation_score, 3),
            'timing_score': round(self.timing_score, 3),
            'volume_score': round(self.volume_score, 3),
            'is_match': self.is_match,
            'entry_guard': f"{self.entry_guard_nickname} ({self.entry_guard_ip})",
            'origin_ip': self.local_origin_ip,
            'evidence': self.evidence
        }


class RealTimeCorrelationEngine:
    """
    Real-Time Correlation Attack Engine.
    
    Continuously captures packets, identifies TOR traffic,
    and performs live correlation analysis.
    """
    
    def __init__(self, 
                 tor_relay_ips: Dict[str, Dict] = None,
                 max_flows: int = 100,
                 correlation_window: float = 30.0):
        """
        Initialize real-time engine.
        
        Args:
            tor_relay_ips: Dict mapping IPs to relay info
            max_flows: Maximum flows to track
            correlation_window: Time window for correlation (seconds)
        """
        self.tor_relay_ips = tor_relay_ips or {}
        self.max_flows = max_flows
        self.correlation_window = correlation_window
        
        # Flow tracking
        self._flows: Dict[str, LiveFlow] = {}
        self._tor_flows: Dict[str, LiveFlow] = {}
        
        # Correlation results
        self._correlations: deque = deque(maxlen=50)
        
        # Capture state
        self._capturing = False
        self._capture_thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._start_time = 0.0
        
        # Callbacks
        self._on_correlation: Optional[Callable] = None
        self._on_packet: Optional[Callable] = None
        self._local_ip = ""
    
    def set_tor_relays(self, relay_ips: Dict[str, Dict]):
        """Update TOR relay IP database."""
        self.tor_relay_ips = relay_ips
    
    def set_local_ip(self, ip: str):
        """Set the local machine IP."""
        self._local_ip = ip
    
    def on_correlation(self, callback: Callable[[RealTimeCorrelation], None]):
        """Register callback for correlation events."""
        self._on_correlation = callback
    
    def on_packet(self, callback: Callable[[LivePacket], None]):
        """Register callback for packet events."""
        self._on_packet = callback
    
    def process_packet(self, pkt: LivePacket):
        """
        Process a captured packet in real-time.
        
        Args:
            pkt: Captured packet
        """
        self._packet_count += 1
        
        # Notify callback
        if self._on_packet:
            self._on_packet(pkt)
        
        # Create flow key
        flow_key = f"{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}"
        
        # Get or create flow
        if flow_key not in self._flows:
            flow = LiveFlow(
                flow_id=flow_key,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip
            )
            self._flows[flow_key] = flow
            
            # Check if TOR traffic
            self._check_tor_flow(flow)
            
            # Limit flows
            if len(self._flows) > self.max_flows:
                oldest = min(self._flows, key=lambda k: self._flows[k].last_seen)
                del self._flows[oldest]
        
        # Add packet to flow
        self._flows[flow_key].add_packet(pkt)
        
        # Run correlation if TOR flow
        if self._flows[flow_key].is_tor:
            self._run_correlation(self._flows[flow_key])
    
    def _check_tor_flow(self, flow: LiveFlow):
        """Check if flow is TOR traffic and identify relay type."""
        # Check destination
        if flow.dst_ip in self.tor_relay_ips:
            relay = self.tor_relay_ips[flow.dst_ip]
            flow.is_tor = True
            flow.tor_role = relay.get('role', 'Relay')
            flow.relay_nickname = relay.get('nickname', 'Unknown')
            self._tor_flows[flow.flow_id] = flow
        
        # Check source (incoming TOR traffic)
        elif flow.src_ip in self.tor_relay_ips:
            relay = self.tor_relay_ips[flow.src_ip]
            flow.is_tor = True
            flow.tor_role = relay.get('role', 'Relay')
            flow.relay_nickname = relay.get('nickname', 'Unknown')
            self._tor_flows[flow.flow_id] = flow
    
    def _run_correlation(self, flow: LiveFlow):
        """
        Run real-time correlation on a TOR flow.
        
        Args:
            flow: TOR flow to analyze
        """
        if len(flow.packets) < 5:
            return  # Need minimum packets
        
        evidence = []
        
        # Timing analysis
        iats = flow.get_iat_sequence()
        timing_score = 0.0
        
        if len(iats) >= 3:
            mean_iat = statistics.mean(iats)
            std_iat = statistics.stdev(iats) if len(iats) > 1 else 0
            cv = std_iat / mean_iat if mean_iat > 0 else 1
            
            # TOR typically has regular timing patterns
            if 0.05 <= mean_iat <= 2.0:
                timing_score = 0.8
                evidence.append(f"IAT pattern consistent with TOR ({mean_iat:.3f}s avg)")
            
            if cv < 0.5:
                timing_score = min(1.0, timing_score + 0.2)
                evidence.append(f"Regular timing detected (CV={cv:.2f})")
        
        # Volume analysis
        volume_score = 0.0
        avg_size = flow.total_bytes / len(flow.packets) if flow.packets else 0
        
        # TOR cells are typically 512 bytes
        if 400 <= avg_size <= 600:
            volume_score = 0.9
            evidence.append(f"Packet size consistent with TOR cells ({avg_size:.0f} bytes avg)")
        elif 200 <= avg_size <= 800:
            volume_score = 0.6
            evidence.append(f"Packet size in TOR range ({avg_size:.0f} bytes)")
        
        # Combined score
        correlation_score = timing_score * 0.6 + volume_score * 0.4
        is_match = correlation_score >= 0.65
        
        if is_match:
            evidence.append(f"HIGH CORRELATION: TOR Entry Guard traffic detected!")
        
        # Determine origin IP
        origin_ip = flow.src_ip if flow.dst_ip in self.tor_relay_ips else flow.dst_ip
        if not self._local_ip:
            self._local_ip = origin_ip
        
        # Create correlation result
        result = RealTimeCorrelation(
            timestamp=time.time(),
            entry_flow=flow.flow_id,
            correlation_score=correlation_score,
            timing_score=timing_score,
            volume_score=volume_score,
            is_match=is_match,
            entry_guard_ip=flow.dst_ip if flow.dst_ip in self.tor_relay_ips else flow.src_ip,
            entry_guard_nickname=flow.relay_nickname,
            local_origin_ip=origin_ip,
            evidence=evidence
        )
        
        self._correlations.append(result)
        
        # Notify callback
        if self._on_correlation and is_match:
            self._on_correlation(result)
    
    def start_capture(self, interface: str = None, duration: float = 30.0):
        """
        Start live packet capture.
        
        Args:
            interface: Network interface (None for default)
            duration: Capture duration in seconds
        """
        if self._capturing:
            return
        
        self._capturing = True
        self._start_time = time.time()
        self._packet_count = 0
        
        def capture_thread():
            try:
                from scapy.all import sniff
                
                def packet_handler(pkt):
                    if not self._capturing:
                        return
                    
                    if pkt.haslayer('IP'):
                        ip_layer = pkt['IP']
                        src_port = dst_port = 0
                        proto = "OTHER"
                        
                        if pkt.haslayer('TCP'):
                            src_port = pkt['TCP'].sport
                            dst_port = pkt['TCP'].dport
                            proto = "TCP"
                        elif pkt.haslayer('UDP'):
                            src_port = pkt['UDP'].sport
                            dst_port = pkt['UDP'].dport
                            proto = "UDP"
                        
                        live_pkt = LivePacket(
                            timestamp=time.time(),
                            src_ip=ip_layer.src,
                            dst_ip=ip_layer.dst,
                            src_port=src_port,
                            dst_port=dst_port,
                            size=len(pkt),
                            protocol=proto
                        )
                        
                        self.process_packet(live_pkt)
                
                sniff(
                    iface=interface,
                    prn=packet_handler,
                    timeout=duration,
                    filter="tcp or udp",
                    store=False
                )
                
            except ImportError:
                print("Scapy not available for live capture")
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self._capturing = False
        
        self._capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self._capture_thread.start()
    
    def stop_capture(self):
        """Stop live capture."""
        self._capturing = False
        if self._capture_thread:
            self._capture_thread.join(timeout=2.0)
    
    def is_capturing(self) -> bool:
        """Check if currently capturing."""
        return self._capturing
    
    def get_status(self) -> Dict:
        """Get current capture status."""
        runtime = time.time() - self._start_time if self._start_time else 0
        
        return {
            'capturing': self._capturing,
            'runtime': round(runtime, 1),
            'packets_captured': self._packet_count,
            'total_flows': len(self._flows),
            'tor_flows': len(self._tor_flows),
            'correlations': len(self._correlations),
            'local_ip': self._local_ip
        }
    
    def get_flows(self) -> List[Dict]:
        """Get all tracked flows."""
        return [f.to_dict() for f in self._flows.values()]
    
    def get_tor_flows(self) -> List[Dict]:
        """Get TOR flows only."""
        return [f.to_dict() for f in self._tor_flows.values()]
    
    def get_correlations(self) -> List[Dict]:
        """Get correlation results."""
        return [c.to_dict() for c in self._correlations]
    
    def get_latest_correlation(self) -> Optional[Dict]:
        """Get most recent correlation."""
        if self._correlations:
            return self._correlations[-1].to_dict()
        return None
    
    def clear(self):
        """Clear all data."""
        self._flows.clear()
        self._tor_flows.clear()
        self._correlations.clear()
        self._packet_count = 0


# Singleton instance
_realtime_engine: Optional[RealTimeCorrelationEngine] = None


def get_realtime_engine() -> RealTimeCorrelationEngine:
    """Get singleton real-time engine instance."""
    global _realtime_engine
    if _realtime_engine is None:
        _realtime_engine = RealTimeCorrelationEngine()
    return _realtime_engine


def build_tor_relay_database(raw_relays: List[Dict]) -> Dict[str, Dict]:
    """
    Build IP-to-relay lookup from raw consensus data.
    
    Args:
        raw_relays: List of relay dicts from Onionoo
        
    Returns:
        Dict mapping IP to relay info
    """
    relay_db = {}
    
    for r in raw_relays:
        or_addr = r.get('or_addresses', [''])[0]
        ip = or_addr.rsplit(':', 1)[0].strip('[]') if or_addr else ''
        
        if ip:
            flags = r.get('flags', [])
            role = 'Entry Guard' if 'Guard' in flags else ('Exit Node' if 'Exit' in flags else 'Relay')
            
            relay_db[ip] = {
                'nickname': r.get('nickname', 'Unknown'),
                'role': role,
                'flags': flags,
                'country': r.get('country_name', 'Unknown'),
                'bandwidth': r.get('bandwidth', 0)
            }
    
    return relay_db
