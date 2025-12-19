"""
Entry Guard Analyzer Module.

Detects TOR Entry Guard connections using multiple indicators:
- TOR consensus IP matching
- Localhost SOCKS proxy detection (127.0.0.1:9050/9150)
- TLS fingerprinting
- Packet size analysis (512-byte cells)
- Inter-arrival time patterns
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.constants import (
    TOR_RELAY_PREFIXES,
    TOR_PORTS,
    TOR_CELL_SIZES,
    TOR_SOCKS_PORTS,
    LOCALHOST_IPS,
    TOR_ORPORTS,
    TrafficType,
    CONFIDENCE_THRESHOLDS,
    TOR_PACKET_SIZE_RANGE
)
from utils.helpers import (
    is_tor_relay,
    is_tor_port,
    is_tor_cell_size,
    check_iat_pattern
)


@dataclass
class EntryGuardResult:
    """Result of Entry Guard detection analysis."""
    traffic_type: TrafficType
    confidence: float
    indicators: List[str] = field(default_factory=list)
    relay_ip: Optional[str] = None
    relay_port: Optional[int] = None
    is_bridge: bool = False
    is_socks_proxy: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for display."""
        return {
            'traffic_type': self.traffic_type.value,
            'confidence': round(self.confidence, 2),
            'indicators': self.indicators,
            'relay_ip': self.relay_ip,
            'relay_port': self.relay_port,
            'is_bridge': self.is_bridge,
            'is_socks_proxy': self.is_socks_proxy
        }


class EntryGuardAnalyzer:
    """
    Analyzes network flows to detect TOR Entry Guard connections.
    
    Detection is based on multiple indicators with weighted scoring:
    1. DEFINITIVE: Localhost SOCKS proxy (127.0.0.1:9050/9150)
    2. DEFINITIVE: TOR relay ports (9001, 9030)
    3. STRONG: Known TOR relay IP addresses
    4. STRONG: TLS + known relay IP
    5. MEDIUM: TOR cell size patterns
    6. WEAK: IAT patterns consistent with TOR
    """
    
    # Class-level cache for live relay IPs from consensus
    _live_relay_ips: set = set()
    
    def __init__(self):
        """Initialize Entry Guard Analyzer."""
        # Custom relay IPs can be added here
        self.custom_relay_ips: set = set()
        
    def add_custom_relay(self, ip: str):
        """Add a custom relay IP address."""
        self.custom_relay_ips.add(ip)
    
    @classmethod
    def load_live_relays(cls, relay_ips: list):
        """
        Load live relay IPs from TOR consensus.
        
        Args:
            relay_ips: List of relay IP addresses from consensus
        """
        cls._live_relay_ips = set(relay_ips)
        print(f"[EntryGuardAnalyzer] Loaded {len(cls._live_relay_ips)} live relay IPs")
    
    @classmethod
    def get_relay_count(cls) -> int:
        """Get number of loaded relay IPs."""
        return len(cls._live_relay_ips)
    
    def _is_localhost(self, ip: str) -> bool:
        """Check if IP is localhost."""
        return ip in LOCALHOST_IPS or ip.startswith('127.')
    
    def _check_tor_ip(self, ip: str) -> bool:
        """Check if IP is a known TOR relay (static + live consensus)."""
        # Check static prefixes
        if is_tor_relay(ip):
            return True
        # Check custom added relays
        if ip in self.custom_relay_ips:
            return True
        # Check live consensus relays (class-level cache)
        if ip in self._live_relay_ips:
            return True
        return False
    
    def _check_tor_port(self, port: int) -> tuple:
        """
        Check if port is TOR-related.
        
        Returns:
            (is_tor_port, port_type)
        """
        if port == 9001 or port == 9030:
            return True, "ORPort"
        elif port in TOR_SOCKS_PORTS:
            return True, "SOCKS"
        elif port == 443:
            return True, "HTTPS"  # Common for relays
        elif port == 80:
            return True, "HTTP"  # Some relays
        return False, None
    
    def _check_cell_sizes(self, packet_sizes: List[int]) -> tuple:
        """
        Analyze packet sizes for TOR cell patterns.
        
        Returns:
            (matches, ratio) - number of matches and ratio of matching packets
        """
        if not packet_sizes:
            return 0, 0.0
        
        matches = sum(1 for size in packet_sizes if is_tor_cell_size(size))
        ratio = matches / len(packet_sizes)
        return matches, ratio
    
    def _check_size_range(self, packet_sizes: List[int]) -> tuple:
        """
        Check if packet sizes fall within TOR's typical range.
        
        Returns:
            (in_range_count, ratio)
        """
        if not packet_sizes:
            return 0, 0.0
        
        min_size, max_size = TOR_PACKET_SIZE_RANGE
        in_range = sum(1 for size in packet_sizes if min_size <= size <= max_size)
        ratio = in_range / len(packet_sizes)
        return in_range, ratio
    
    def _analyze_iat(self, iat_mean: float, iat_std: float) -> bool:
        """Check if IAT pattern matches TOR traffic."""
        return check_iat_pattern(iat_mean, iat_std)
    
    def _is_non_tor_traffic(self, dst_ip: str, dst_port: int, src_port: int) -> bool:
        """
        Check if traffic is definitely NOT TOR based on exclusion rules.
        
        Returns True for:
        - Multicast addresses (224.x, 239.x)
        - Broadcast addresses (255.x, x.x.x.255)
        - DNS, mDNS, LLMNR, NetBIOS, SSDP ports
        - Private network traffic (10.x, 192.168.x) unless to TOR ports
        """
        # Multicast
        if dst_ip.startswith('224.') or dst_ip.startswith('239.'):
            return True
        
        # Broadcast
        if dst_ip.startswith('255.') or dst_ip.endswith('.255'):
            return True
        
        # Link-local
        if dst_ip.startswith('169.254.'):
            return True
        
        # DNS (port 53)
        if dst_port == 53 or src_port == 53:
            return True
        
        # mDNS (port 5353)
        if dst_port == 5353 or src_port == 5353:
            return True
        
        # LLMNR (port 5355)
        if dst_port == 5355 or src_port == 5355:
            return True
        
        # SSDP/UPnP (port 1900)
        if dst_port == 1900 or src_port == 1900:
            return True
        
        # WS-Discovery (port 3702)
        if dst_port == 3702 or src_port == 3702:
            return True
        
        # NetBIOS (ports 137, 138, 139)
        if dst_port in [137, 138, 139] or src_port in [137, 138, 139]:
            return True
        
        # Private networks (unless going to TOR ports)
        tor_ports = [9001, 9030, 9050, 9150, 9051]
        if dst_ip.startswith('10.') and dst_port not in tor_ports:
            return True
        if dst_ip.startswith('192.168.') and dst_port not in tor_ports:
            return True
        
        return False
    
    def detect_entry_guard(self, flow_info: Dict) -> EntryGuardResult:
        """
        Detect if a flow represents a TOR Entry Guard connection.
        
        Args:
            flow_info: Dictionary containing flow information:
                - dst_ip: Destination IP
                - dst_port: Destination port
                - src_ip: Source IP (optional)
                - src_port: Source port (optional)
                - avg_packet_size: Average packet size (optional)
                - tls_handshake_detected: TLS detected (optional)
                - iat_mean: Mean IAT (optional)
                - iat_std: IAT std dev (optional)
                - packet_sizes: List of packet sizes (optional)
                
        Returns:
            EntryGuardResult with detection results
        """
        dst_ip = flow_info.get('dst_ip', '')
        dst_port = flow_info.get('dst_port', 0)
        src_ip = flow_info.get('src_ip', '')
        src_port = flow_info.get('src_port', 0)
        avg_size = flow_info.get('avg_packet_size', 0)
        tls_detected = flow_info.get('tls_handshake_detected', False)
        iat_mean = flow_info.get('iat_mean', 0)
        iat_std = flow_info.get('iat_std', 0)
        packet_sizes = flow_info.get('packet_sizes', [])
        
        # ========== EXCLUSION CHECK ==========
        # Return immediately for known non-TOR traffic
        if self._is_non_tor_traffic(dst_ip, dst_port, src_port):
            return EntryGuardResult(
                traffic_type=TrafficType.NON_TOR,
                confidence=0.0,
                indicators=[],
                relay_ip=None,
                relay_port=None,
                is_bridge=False,
                is_socks_proxy=False
            )
        
        # ========== TOR DETECTION ==========
        indicators = []
        confidence = 0.0
        traffic_type = TrafficType.NON_TOR
        is_bridge = False
        is_socks_proxy = False
        packet_sizes = flow_info.get('packet_sizes', [])
        
        # ===== Check 1: Localhost SOCKS Proxy (DEFINITIVE) =====
        # TOR Browser connects to localhost:9150 or tor daemon to localhost:9050
        if self._is_localhost(dst_ip) and dst_port in TOR_SOCKS_PORTS:
            indicators.append(f"TOR SOCKS Proxy (localhost:{dst_port})")
            confidence += 0.95
            traffic_type = TrafficType.TOR_SOCKS
            is_socks_proxy = True
        
        # Also check if source is from SOCKS port (return traffic)
        if self._is_localhost(src_ip) and src_port in TOR_SOCKS_PORTS:
            indicators.append(f"TOR SOCKS Proxy response (localhost:{src_port})")
            confidence += 0.80
            traffic_type = TrafficType.TOR_SOCKS
            is_socks_proxy = True
        
        # ===== Check 2: TOR relay ports (DEFINITIVE) =====
        is_tor_dst_port, port_type = self._check_tor_port(dst_port)
        
        if dst_port in [9001, 9030]:  # Definitive TOR ORPorts
            indicators.append(f"TOR {port_type} port {dst_port}")
            confidence += 0.60
            if traffic_type == TrafficType.NON_TOR:
                traffic_type = TrafficType.TOR_ENTRY_GUARD
        
        # ===== Check 3: Known TOR relay IP (STRONG) =====
        if self._check_tor_ip(dst_ip):
            indicators.append(f"TOR consensus relay IP ({dst_ip[:12]}...)")
            confidence += 0.50
            if traffic_type == TrafficType.NON_TOR:
                traffic_type = TrafficType.TOR_ENTRY_GUARD
        
        # ===== Check 4: TLS + TOR IP/Port (STRONG) =====
        if tls_detected:
            if self._check_tor_ip(dst_ip):
                indicators.append("TLS encrypted + TOR relay IP")
                confidence += 0.25
            elif dst_port in TOR_ORPORTS:
                indicators.append("TLS encrypted + TOR ORPort")
                confidence += 0.20
            elif dst_port == 443 and not self._is_localhost(dst_ip):
                # HTTPS to external - could be TOR disguised
                confidence += 0.05
        
        # ===== Check 5: Cell size analysis (MEDIUM) =====
        if packet_sizes:
            matches, ratio = self._check_cell_sizes(packet_sizes)
            if ratio > 0.4:  # 40%+ match TOR cell sizes
                indicators.append(f"TOR cell size pattern ({ratio*100:.0f}% match)")
                confidence += 0.25
                if traffic_type == TrafficType.NON_TOR and confidence > 0.3:
                    traffic_type = TrafficType.TOR_BRIDGE
            elif ratio > 0.2:
                indicators.append(f"Partial TOR cell pattern ({ratio*100:.0f}% match)")
                confidence += 0.12
            
            # Also check the size range
            _, range_ratio = self._check_size_range(packet_sizes)
            if range_ratio > 0.5:
                indicators.append(f"Packet sizes in TOR range ({range_ratio*100:.0f}%)")
                confidence += 0.10
                
        elif avg_size and is_tor_cell_size(int(avg_size)):
            indicators.append(f"TOR cell size (~{int(avg_size)} bytes)")
            confidence += 0.15
        
        # ===== Check 6: IAT pattern (WEAK) =====
        if iat_mean > 0 and iat_std >= 0:
            if self._analyze_iat(iat_mean, iat_std):
                indicators.append("IAT pattern consistent with TOR")
                confidence += 0.10
        
        # ===== Check for Bridge (hidden entry point) =====
        # Bridges don't use standard TOR ports but have TOR characteristics
        if traffic_type == TrafficType.NON_TOR and confidence > 0.2:
            if not self._check_tor_ip(dst_ip) and dst_port not in [9001, 9030, 9050, 9150]:
                if tls_detected and packet_sizes:
                    _, ratio = self._check_cell_sizes(packet_sizes)
                    if ratio > 0.3:
                        indicators.append("Possible TOR Bridge (hidden relay)")
                        traffic_type = TrafficType.TOR_BRIDGE
                        is_bridge = True
                        confidence += 0.15
        
        # ===== Check for VPN patterns =====
        if traffic_type == TrafficType.NON_TOR and confidence < 0.2:
            # VPN typically uses: OpenVPN (1194), WireGuard (51820), IKEv2 (500, 4500)
            vpn_ports = {1194, 51820, 500, 4500, 1701, 1723}
            if dst_port in vpn_ports:
                indicators.append(f"VPN port {dst_port}")
                traffic_type = TrafficType.VPN
                confidence = 0.7
        
        # ===== ML Classification (Enhanced Detection) =====
        # Use ML classifier for flows that haven't been definitively classified
        if traffic_type == TrafficType.NON_TOR and confidence < 0.5:
            try:
                from models.ml_tor_classifier import get_ml_classifier, FlowStats
                
                # Build flow stats
                total_packets = flow_info.get('total_packets', len(packet_sizes) if packet_sizes else 10)
                total_bytes = flow_info.get('total_bytes', int(avg_size * total_packets) if avg_size else 5000)
                duration = flow_info.get('duration', 1.0)
                
                ml_flow = FlowStats(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=6
                )
                ml_flow.duration = duration
                ml_flow.total_bytes = total_bytes
                ml_flow.total_packets = total_packets
                ml_flow.packet_sizes = packet_sizes if packet_sizes else [int(avg_size)] * total_packets if avg_size else []
                
                # Generate synthetic timestamps based on IAT
                if iat_mean > 0:
                    for i in range(total_packets):
                        ml_flow.timestamps.append(i * iat_mean)
                        if i % 2 == 0:
                            ml_flow.fwd_timestamps.append(i * iat_mean)
                        else:
                            ml_flow.bwd_timestamps.append(i * iat_mean)
                
                ml_clf = get_ml_classifier()
                result = ml_clf.predict_flow(ml_flow)
                
                if result['is_tor'] and result['confidence'] > 0.6:
                    traffic_type = TrafficType.TOR_BRIDGE  # ML detected TOR (likely bridge)
                    confidence = result['confidence']
                    indicators.append(f"🤖 ML Classification: TOR ({result['confidence']:.0%})")
                    is_bridge = True
                elif result['is_tor'] and result['confidence'] > 0.4:
                    # Boost existing confidence
                    confidence += 0.25
                    indicators.append(f"🤖 ML boost: TOR-like patterns ({result['confidence']:.0%})")
                    
            except Exception as e:
                pass  # ML not available, continue with rule-based
        
        # Also try ML for uncertain TOR classifications to boost confidence
        if traffic_type in [TrafficType.TOR_ENTRY_GUARD, TrafficType.TOR_BRIDGE] and confidence < 0.7:
            try:
                from models.ml_tor_classifier import get_ml_classifier, FlowStats
                ml_clf = get_ml_classifier()
                
                ml_flow = FlowStats(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=6)
                ml_flow.packet_sizes = packet_sizes if packet_sizes else [int(avg_size or 512)] * 10
                ml_flow.duration = flow_info.get('duration', 1.0)
                
                result = ml_clf.predict_flow(ml_flow)
                if result['is_tor']:
                    confidence = max(confidence, result['confidence'])
                    indicators.append(f"🤖 ML confirmed TOR ({result['confidence']:.0%})")
            except:
                pass
        
        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)
        
        # Lower threshold for classification - much more aggressive
        if traffic_type in [TrafficType.TOR_ENTRY_GUARD, TrafficType.TOR_BRIDGE, TrafficType.TOR_SOCKS]:
            if confidence < 0.10:  # Very very low threshold
                traffic_type = TrafficType.NON_TOR
        
        return EntryGuardResult(
            traffic_type=traffic_type,
            confidence=confidence,
            indicators=indicators,
            relay_ip=dst_ip if traffic_type != TrafficType.NON_TOR else None,
            relay_port=dst_port if traffic_type != TrafficType.NON_TOR else None,
            is_bridge=is_bridge,
            is_socks_proxy=is_socks_proxy
        )
    
    def analyze_flows(self, flows: List[Dict]) -> List[EntryGuardResult]:
        """
        Analyze multiple flows for Entry Guard detection.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            List of EntryGuardResult objects
        """
        results = []
        for flow in flows:
            result = self.detect_entry_guard(flow)
            results.append(result)
        return results
    
    def get_tor_flows(self, flows: List[Dict]) -> List[Dict]:
        """
        Filter and return only TOR-related flows.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            List of flows classified as TOR
        """
        tor_flows = []
        for flow in flows:
            result = self.detect_entry_guard(flow)
            if result.traffic_type in [TrafficType.TOR_ENTRY_GUARD, TrafficType.TOR_BRIDGE, TrafficType.TOR_SOCKS]:
                flow['detection_result'] = result.to_dict()
                tor_flows.append(flow)
        return tor_flows

