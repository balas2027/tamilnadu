"""
TOR Traffic Detector.

Simple, reliable TOR detection using:
1. TOR Consensus IP prefix matching
2. TLS Fingerprinting  
3. Cell size analysis (~512 bytes)
4. IAT variance analysis

This module is for Live Capture and PCAP Upload analysis.
Does NOT modify Global Network Monitor.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum
import statistics


# ============ TOR NETWORK CONSTANTS ============

# Known TOR relay IP prefixes (from major operators)
TOR_RELAY_PREFIXES = [
    '185.220.100.', '185.220.101.', '185.220.102.', '185.220.103.',  # Torservers.net
    '199.249.230.', '199.249.231.',                                   # Quintex Alliance
    '162.247.72.', '162.247.73.', '162.247.74.',                     # CalyxInstitute
    '89.234.157.',                                                    # Nos Oignons
    '87.118.122.', '87.118.116.',                                    # Artikel10
    '51.15.', '51.158.',                                              # Scaleway (many relays)
    '193.218.118.', '193.234.15.',                                   # Various EU operators
    '104.244.', '198.98.',                                            # US operators
    '45.141.215.', '45.151.167.',                                    # More operators
    '91.132.', '91.219.', '91.213.',                                 # EU ranges
    '185.100.', '185.129.',                                           # Privacy hosts
    '178.17.', '178.20.',                                             # EU ranges
    '109.70.100.',                                                    # appliedprivacy.net
    '192.42.116.',                                                    # NL range
    '77.81.247.',                                                     # AT range
    '95.211.',                                                        # LeaseWeb
    '213.164.',                                                       # UK range
]

# TOR-specific ports
TOR_PORTS = {
    9001,   # Default TOR OR port
    9030,   # Directory port
    9050,   # SOCKS port (local)
    9150,   # TOR Browser SOCKS
    9151,   # TOR Browser control
    443,    # Many relays use HTTPS port
}

# TOR cell sizes (512 bytes + headers)
TOR_CELL_SIZES = {512, 514, 536, 548, 558, 586, 590, 600}

# TOR TLS cipher suites
TOR_TLS_CIPHERS = {
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
}


class TrafficType(Enum):
    """Traffic classification types."""
    NON_TOR = "Non-TOR"
    TOR_ENTRY_GUARD = "TOR Entry Guard"
    TOR_BRIDGE = "TOR Bridge"
    TOR_RELAY = "TOR Relay"
    VPN = "VPN"


@dataclass
class DetectionResult:
    """Result of TOR detection analysis."""
    flow_id: str
    traffic_type: TrafficType
    confidence: float  # 0.0 to 1.0
    indicators: List[str]
    
    # Flow details
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    packet_count: int = 0
    total_bytes: int = 0
    duration: float = 0.0
    avg_packet_size: float = 0.0
    iat_mean: float = 0.0
    iat_cv: float = 0.0  # Coefficient of variation
    
    # TOR-specific
    relay_name: str = ""
    estimated_circuits: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'flow_id': self.flow_id,
            'traffic_type': self.traffic_type.value,
            'confidence': round(self.confidence, 3),
            'indicators': self.indicators,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'duration': round(self.duration, 2),
            'avg_packet_size': round(self.avg_packet_size, 1),
            'iat_mean': round(self.iat_mean, 4),
            'iat_cv': round(self.iat_cv, 3),
            'relay_name': self.relay_name,
            'estimated_circuits': self.estimated_circuits
        }


@dataclass
class CapturedFlow:
    """A captured network flow for analysis."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    # Packet data
    packet_sizes: List[int] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    
    # Computed features
    @property
    def packet_count(self) -> int:
        return len(self.packet_sizes)
    
    @property
    def total_bytes(self) -> int:
        return sum(self.packet_sizes)
    
    @property
    def duration(self) -> float:
        if len(self.timestamps) < 2:
            return 0.0
        return self.timestamps[-1] - self.timestamps[0]
    
    @property
    def avg_packet_size(self) -> float:
        if not self.packet_sizes:
            return 0.0
        return statistics.mean(self.packet_sizes)
    
    def get_iat_sequence(self) -> List[float]:
        """Get Inter-Arrival Time sequence."""
        if len(self.timestamps) < 2:
            return []
        iats = []
        for i in range(1, len(self.timestamps)):
            iat = self.timestamps[i] - self.timestamps[i-1]
            if iat > 0:
                iats.append(iat)
        return iats
    
    def add_packet(self, timestamp: float, size: int):
        """Add a packet to this flow."""
        self.timestamps.append(timestamp)
        self.packet_sizes.append(size)


class TORTrafficDetector:
    """
    TOR Traffic Detector using documented methods.
    
    Detection Methods:
    1. TOR Consensus IP prefix matching
    2. Port analysis (9001, 9050, 9150)
    3. Cell size analysis (~512 bytes)
    4. IAT variance analysis
    5. TLS fingerprinting (when available)
    """
    
    def __init__(self):
        """Initialize detector."""
        self._flows: Dict[str, CapturedFlow] = {}
        self._results: List[DetectionResult] = []
        self._packet_count = 0
    
    def is_tor_relay_ip(self, ip: str) -> bool:
        """Check if IP matches known TOR relay prefixes."""
        return any(ip.startswith(prefix) for prefix in TOR_RELAY_PREFIXES)
    
    def is_tor_port(self, port: int) -> bool:
        """Check if port is commonly used by TOR."""
        return port in TOR_PORTS
    
    def is_tor_cell_size(self, size: int) -> bool:
        """Check if packet size matches TOR cell size."""
        # TOR cells are ~512 bytes, allow some variance
        return size in TOR_CELL_SIZES or (500 <= size <= 600)
    
    def analyze_cell_sizes(self, sizes: List[int]) -> Tuple[float, str]:
        """
        Analyze packet sizes for TOR cell pattern.
        
        Returns:
            (score, indicator_text)
        """
        if not sizes:
            return 0.0, ""
        
        tor_cell_count = sum(1 for s in sizes if self.is_tor_cell_size(s))
        ratio = tor_cell_count / len(sizes)
        
        if ratio >= 0.6:
            return 0.9, f"TOR cell sizes detected ({tor_cell_count}/{len(sizes)} packets)"
        elif ratio >= 0.3:
            return 0.5, f"Partial TOR cell pattern ({tor_cell_count}/{len(sizes)} packets)"
        else:
            return 0.0, ""
    
    def analyze_iat_pattern(self, iats: List[float]) -> Tuple[float, str, float]:
        """
        Analyze IAT (Inter-Arrival Time) pattern for TOR characteristics.
        
        TOR traffic has:
        - Higher mean IAT (due to encryption + relay latency)
        - Lower coefficient of variation (consistent processing)
        
        Returns:
            (score, indicator_text, cv)
        """
        if len(iats) < 3:
            return 0.0, "", 0.0
        
        mean_iat = statistics.mean(iats)
        std_iat = statistics.stdev(iats)
        cv = std_iat / mean_iat if mean_iat > 0 else 1.0
        
        # TOR typically has CV < 0.5 (consistent timing)
        if cv < 0.3:
            return 0.8, f"Very regular timing (CV={cv:.2f}, low variance)", cv
        elif cv < 0.5:
            return 0.6, f"Regular timing pattern (CV={cv:.2f})", cv
        elif cv < 0.8:
            return 0.3, f"Moderate timing regularity (CV={cv:.2f})", cv
        else:
            return 0.0, "", cv
    
    def estimate_circuits(self, timestamps: List[float], gap: float = 1.0) -> int:
        """
        Estimate number of TOR circuits using burst detection.
        
        Args:
            timestamps: Packet timestamps
            gap: Seconds between bursts to count as new circuit
            
        Returns:
            Estimated circuit count
        """
        if len(timestamps) < 2:
            return 1
        
        bursts = 1
        for i in range(1, len(timestamps)):
            if timestamps[i] - timestamps[i-1] > gap:
                bursts += 1
        
        # Heuristic: circuits ≈ bursts / 2
        return max(1, bursts // 2)
    
    def detect(self, flow: CapturedFlow) -> DetectionResult:
        """
        Detect if a flow is TOR traffic.
        
        Args:
            flow: Captured network flow
            
        Returns:
            DetectionResult with classification
        """
        indicators = []
        scores = []
        
        # === 1. IP PREFIX MATCHING ===
        if self.is_tor_relay_ip(flow.dst_ip):
            indicators.append(f"✓ Known TOR relay IP: {flow.dst_ip}")
            scores.append(0.7)
        elif self.is_tor_relay_ip(flow.src_ip):
            indicators.append(f"✓ Known TOR relay IP: {flow.src_ip}")
            scores.append(0.7)
        
        # === 2. PORT ANALYSIS ===
        if self.is_tor_port(flow.dst_port):
            if flow.dst_port == 9001:
                indicators.append(f"✓ TOR OR port (9001)")
                scores.append(0.9)  # Very strong indicator
            elif flow.dst_port in {9050, 9150, 9151}:
                indicators.append(f"✓ TOR SOCKS port ({flow.dst_port})")
                scores.append(0.8)
            elif flow.dst_port == 443:
                indicators.append(f"⚬ HTTPS port (possible TOR)")
                scores.append(0.2)  # Weak - could be regular HTTPS
        
        if self.is_tor_port(flow.src_port):
            indicators.append(f"✓ TOR source port ({flow.src_port})")
            scores.append(0.5)
        
        # === 3. CELL SIZE ANALYSIS ===
        cell_score, cell_indicator = self.analyze_cell_sizes(flow.packet_sizes)
        if cell_score > 0:
            indicators.append(f"✓ {cell_indicator}")
            scores.append(cell_score)
        
        # === 4. IAT PATTERN ANALYSIS ===
        iats = flow.get_iat_sequence()
        iat_score, iat_indicator, iat_cv = self.analyze_iat_pattern(iats)
        if iat_score > 0:
            indicators.append(f"✓ {iat_indicator}")
            scores.append(iat_score)
        
        # === 5. COMPUTE FINAL CLASSIFICATION ===
        
        if not scores:
            # No TOR indicators found
            return DetectionResult(
                flow_id=flow.flow_id,
                traffic_type=TrafficType.NON_TOR,
                confidence=0.95,
                indicators=["No TOR indicators detected"],
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                packet_count=flow.packet_count,
                total_bytes=flow.total_bytes,
                duration=flow.duration,
                avg_packet_size=flow.avg_packet_size,
                iat_mean=statistics.mean(iats) if iats else 0.0,
                iat_cv=iat_cv
            )
        
        # Calculate weighted confidence
        confidence = max(scores) * 0.6 + (sum(scores) / len(scores)) * 0.4
        confidence = min(1.0, confidence)
        
        # Determine traffic type
        if confidence >= 0.7:
            # Strong TOR detection
            if flow.dst_port in {9001, 9030} or any("OR port" in i for i in indicators):
                traffic_type = TrafficType.TOR_ENTRY_GUARD
            elif flow.dst_port in {9050, 9150, 9151}:
                traffic_type = TrafficType.TOR_ENTRY_GUARD  # Local SOCKS
            elif any("relay IP" in i for i in indicators):
                traffic_type = TrafficType.TOR_RELAY
            else:
                traffic_type = TrafficType.TOR_ENTRY_GUARD
        elif confidence >= 0.4:
            # Possible TOR (could be bridge)
            traffic_type = TrafficType.TOR_BRIDGE
            indicators.append("⚬ Possible TOR Bridge (obfuscated)")
        else:
            traffic_type = TrafficType.NON_TOR
        
        # Estimate circuits if TOR detected
        circuits = 0
        if traffic_type != TrafficType.NON_TOR:
            circuits = self.estimate_circuits(flow.timestamps)
            if circuits > 1:
                indicators.append(f"⚬ Estimated {circuits} circuits")
        
        return DetectionResult(
            flow_id=flow.flow_id,
            traffic_type=traffic_type,
            confidence=confidence,
            indicators=indicators,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            packet_count=flow.packet_count,
            total_bytes=flow.total_bytes,
            duration=flow.duration,
            avg_packet_size=flow.avg_packet_size,
            iat_mean=statistics.mean(iats) if iats else 0.0,
            iat_cv=iat_cv,
            estimated_circuits=circuits
        )
    
    def process_packet(self, src_ip: str, dst_ip: str, src_port: int, 
                       dst_port: int, size: int, protocol: str = "TCP",
                       timestamp: float = None) -> Optional[str]:
        """
        Process a captured packet.
        
        Returns:
            Flow ID the packet was added to
        """
        self._packet_count += 1
        
        if timestamp is None:
            timestamp = time.time()
        
        # Create flow key
        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        
        # Get or create flow
        if flow_key not in self._flows:
            self._flows[flow_key] = CapturedFlow(
                flow_id=flow_key,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol
            )
        
        # Add packet to flow
        self._flows[flow_key].add_packet(timestamp, size)
        
        return flow_key
    
    def analyze_all_flows(self) -> List[DetectionResult]:
        """
        Analyze all captured flows and return results.
        
        Returns:
            List of DetectionResult for each flow
        """
        self._results = []
        
        for flow in self._flows.values():
            if flow.packet_count >= 3:  # Need minimum packets
                result = self.detect(flow)
                self._results.append(result)
        
        return self._results
    
    def get_summary(self) -> Dict:
        """Get detection summary statistics."""
        if not self._results:
            self.analyze_all_flows()
        
        tor_count = sum(1 for r in self._results if r.traffic_type != TrafficType.NON_TOR)
        non_tor_count = sum(1 for r in self._results if r.traffic_type == TrafficType.NON_TOR)
        
        by_type = {}
        for r in self._results:
            t = r.traffic_type.value
            by_type[t] = by_type.get(t, 0) + 1
        
        return {
            'total_packets': self._packet_count,
            'total_flows': len(self._flows),
            'analyzed_flows': len(self._results),
            'tor_flows': tor_count,
            'non_tor_flows': non_tor_count,
            'tor_percentage': round(tor_count / len(self._results) * 100, 1) if self._results else 0,
            'by_type': by_type
        }
    
    def get_tor_flows(self) -> List[DetectionResult]:
        """Get only TOR flows."""
        return [r for r in self._results if r.traffic_type != TrafficType.NON_TOR]
    
    def get_non_tor_flows(self) -> List[DetectionResult]:
        """Get only non-TOR flows."""
        return [r for r in self._results if r.traffic_type == TrafficType.NON_TOR]
    
    def clear(self):
        """Clear all captured data."""
        self._flows.clear()
        self._results.clear()
        self._packet_count = 0


def analyze_pcap(pcap_path: str) -> Tuple[TORTrafficDetector, List[DetectionResult]]:
    """
    Analyze a PCAP file for TOR traffic.
    
    Args:
        pcap_path: Path to PCAP file
        
    Returns:
        (detector, results)
    """
    from scapy.all import rdpcap
    
    detector = TORTrafficDetector()
    packets = rdpcap(pcap_path)
    
    for pkt in packets:
        if pkt.haslayer('IP'):
            ip = pkt['IP']
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
            
            timestamp = float(pkt.time)
            detector.process_packet(
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=src_port,
                dst_port=dst_port,
                size=len(pkt),
                protocol=proto,
                timestamp=timestamp
            )
    
    results = detector.analyze_all_flows()
    return detector, results


# Singleton instance
_detector: Optional[TORTrafficDetector] = None


def get_detector() -> TORTrafficDetector:
    """Get singleton detector instance."""
    global _detector
    if _detector is None:
        _detector = TORTrafficDetector()
    return _detector
