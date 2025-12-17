"""
Flow Extractor Module.

Groups individual packets into flows (connections) based on 5-tuple
and extracts statistical features for machine learning classification.
"""

import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import hashlib


@dataclass
class FlowFeatures:
    """
    Statistical features extracted from a network flow.
    
    These features are used for ML-based TOR traffic classification.
    """
    # Flow identification
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    # Basic statistics
    duration: float = 0.0               # Flow duration in seconds
    total_packets: int = 0              # Number of packets
    total_bytes: int = 0                # Total bytes transferred
    
    # Packet statistics
    avg_packet_size: float = 0.0        # Average packet size
    min_packet_size: int = 0            # Minimum packet size
    max_packet_size: int = 0            # Maximum packet size
    std_packet_size: float = 0.0        # Packet size std dev
    
    # Inter-Arrival Time (IAT) statistics
    iat_mean: float = 0.0               # Mean inter-arrival time
    iat_std: float = 0.0                # IAT standard deviation
    iat_min: float = 0.0                # Minimum IAT
    iat_max: float = 0.0                # Maximum IAT
    
    # Rate statistics
    packets_per_second: float = 0.0     # Packet rate
    bytes_per_second: float = 0.0       # Throughput
    
    # First packet info
    initial_packet_size: int = 0        # First packet size (often TLS handshake)
    
    # Protocol indicators
    tls_handshake_detected: bool = False
    
    # Port ratios
    port_443_ratio: float = 0.0         # % packets on port 443
    port_9001_ratio: float = 0.0        # % packets on port 9001
    
    # Entropy
    size_entropy: float = 0.0           # Packet size entropy
    
    # Raw data for advanced analysis
    packet_sizes: List[int] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    
    def to_feature_vector(self) -> np.ndarray:
        """Convert to numpy array for ML models."""
        return np.array([
            self.duration,
            self.total_packets,
            self.total_bytes,
            self.packets_per_second,
            self.bytes_per_second,
            self.avg_packet_size,
            self.iat_mean,
            self.iat_std,
            self.iat_min,
            self.iat_max,
            self.initial_packet_size,
            1.0 if self.tls_handshake_detected else 0.0,
            self.port_443_ratio,
            self.port_9001_ratio,
            self.size_entropy
        ])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for display."""
        return {
            'flow_id': self.flow_id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'duration': round(self.duration, 3),
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'avg_packet_size': round(self.avg_packet_size, 2),
            'iat_mean': round(self.iat_mean, 6),
            'iat_std': round(self.iat_std, 6),
            'packets_per_second': round(self.packets_per_second, 2),
            'tls_detected': self.tls_handshake_detected
        }


class FlowExtractor:
    """
    Extracts and aggregates network flows from packet data.
    
    Groups packets by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
    and computes statistical features for each flow.
    """
    
    def __init__(self, timeout: float = 120.0):
        """
        Initialize FlowExtractor.
        
        Args:
            timeout: Flow timeout in seconds (default 120s)
        """
        self.timeout = timeout
        self.flows: Dict[str, Dict] = {}
        
    def _generate_flow_id(self, src_ip: str, dst_ip: str, 
                          src_port: int, dst_port: int, 
                          protocol: str) -> str:
        """Generate unique flow identifier from 5-tuple."""
        # Create bidirectional flow ID (same ID for both directions)
        endpoints = sorted([
            f"{src_ip}:{src_port}",
            f"{dst_ip}:{dst_port}"
        ])
        flow_str = f"{endpoints[0]}-{endpoints[1]}-{protocol}"
        return hashlib.md5(flow_str.encode()).hexdigest()[:16]
    
    def add_packet(self, packet_info: Dict) -> str:
        """
        Add a packet to flow aggregation.
        
        Args:
            packet_info: Dictionary with packet details:
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - src_port: Source port
                - dst_port: Destination port
                - protocol: Protocol (TCP/UDP)
                - size: Packet size in bytes
                - timestamp: Packet timestamp
                - tls: Whether TLS is detected
                
        Returns:
            Flow ID the packet was added to
        """
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol', 'TCP')
        size = packet_info.get('size', 0)
        timestamp = packet_info.get('timestamp', 0.0)
        tls = packet_info.get('tls', False)
        
        flow_id = self._generate_flow_id(src_ip, dst_ip, src_port, dst_port, protocol)
        
        if flow_id not in self.flows:
            self.flows[flow_id] = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'sizes': [],
                'timestamps': [],
                'tls_detected': False,
                'port_443_count': 0,
                'port_9001_count': 0,
            }
        
        flow = self.flows[flow_id]
        flow['sizes'].append(size)
        flow['timestamps'].append(timestamp)
        
        if tls:
            flow['tls_detected'] = True
        
        if dst_port == 443 or src_port == 443:
            flow['port_443_count'] = flow.get('port_443_count', 0) + 1
        if dst_port == 9001 or src_port == 9001:
            flow['port_9001_count'] = flow.get('port_9001_count', 0) + 1
            
        return flow_id
    
    def _calculate_entropy(self, values: List[int]) -> float:
        """Calculate Shannon entropy of values."""
        if not values:
            return 0.0
        
        from collections import Counter
        import math
        
        counter = Counter(values)
        total = len(values)
        
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)
        
        return entropy
    
    def extract_features(self, flow_id: str) -> Optional[FlowFeatures]:
        """
        Extract statistical features from a flow.
        
        Args:
            flow_id: Flow identifier
            
        Returns:
            FlowFeatures object or None if flow not found
        """
        if flow_id not in self.flows:
            return None
        
        flow = self.flows[flow_id]
        sizes = flow['sizes']
        timestamps = sorted(flow['timestamps'])
        
        if not sizes or not timestamps:
            return None
        
        # Calculate duration
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
        
        # Packet statistics
        total_packets = len(sizes)
        total_bytes = sum(sizes)
        avg_packet_size = np.mean(sizes)
        min_packet_size = min(sizes)
        max_packet_size = max(sizes)
        std_packet_size = np.std(sizes) if len(sizes) > 1 else 0.0
        
        # Inter-arrival time statistics
        if len(timestamps) > 1:
            iats = np.diff(timestamps)
            iat_mean = np.mean(iats)
            iat_std = np.std(iats)
            iat_min = np.min(iats)
            iat_max = np.max(iats)
        else:
            iat_mean = iat_std = iat_min = iat_max = 0.0
        
        # Rate calculations
        if duration > 0:
            packets_per_second = total_packets / duration
            bytes_per_second = total_bytes / duration
        else:
            packets_per_second = bytes_per_second = 0.0
        
        # Port ratios
        port_443_ratio = flow.get('port_443_count', 0) / total_packets if total_packets > 0 else 0.0
        port_9001_ratio = flow.get('port_9001_count', 0) / total_packets if total_packets > 0 else 0.0
        
        # Size entropy
        size_entropy = self._calculate_entropy(sizes)
        
        return FlowFeatures(
            flow_id=flow_id,
            src_ip=flow['src_ip'],
            dst_ip=flow['dst_ip'],
            src_port=flow['src_port'],
            dst_port=flow['dst_port'],
            protocol=flow['protocol'],
            duration=duration,
            total_packets=total_packets,
            total_bytes=total_bytes,
            avg_packet_size=avg_packet_size,
            min_packet_size=min_packet_size,
            max_packet_size=max_packet_size,
            std_packet_size=std_packet_size,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_min=iat_min,
            iat_max=iat_max,
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            initial_packet_size=sizes[0] if sizes else 0,
            tls_handshake_detected=flow.get('tls_detected', False),
            port_443_ratio=port_443_ratio,
            port_9001_ratio=port_9001_ratio,
            size_entropy=size_entropy,
            packet_sizes=sizes.copy(),
            timestamps=timestamps.copy()
        )
    
    def get_all_flows(self) -> List[FlowFeatures]:
        """Extract features from all flows."""
        features = []
        for flow_id in self.flows:
            feat = self.extract_features(flow_id)
            if feat:
                features.append(feat)
        return features
    
    def clear(self):
        """Clear all flows."""
        self.flows.clear()
    
    def get_flow_count(self) -> int:
        """Get number of active flows."""
        return len(self.flows)
