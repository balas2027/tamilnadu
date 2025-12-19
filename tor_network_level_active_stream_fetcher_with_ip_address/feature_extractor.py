"""
Feature Extractor Module.

Extracts ML features from network flows using UNB-CIC dataset approach.
These features are used by the Random Forest classifier for TOR detection.
"""

import statistics
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .flow_tracker import NetworkFlow


@dataclass
class FlowFeatures:
    """
    Flow features for ML classification.
    
    Based on UNB-CIC TOR/Non-TOR dataset features.
    21 features total for Random Forest classification.
    """
    # Basic flow characteristics
    flow_duration: float = 0.0
    flow_bytes_per_sec: float = 0.0
    flow_packets_per_sec: float = 0.0
    
    # IAT (Inter-Arrival Time) statistics
    flow_iat_mean: float = 0.0
    flow_iat_std: float = 0.0
    flow_iat_max: float = 0.0
    flow_iat_min: float = 0.0
    
    # Forward (Fwd) packet statistics
    fwd_packet_length_mean: float = 0.0
    fwd_packet_length_std: float = 0.0
    fwd_packet_length_max: float = 0.0
    fwd_packet_length_min: float = 0.0
    
    # Backward (Bwd) packet statistics (estimated)
    bwd_packet_length_mean: float = 0.0
    bwd_packet_length_std: float = 0.0
    
    # Packet count statistics
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    
    # Size statistics
    packet_length_mean: float = 0.0
    packet_length_std: float = 0.0
    packet_length_variance: float = 0.0
    
    # Active/Idle time
    active_mean: float = 0.0
    idle_mean: float = 0.0
    
    # TOR-specific indicator
    tor_cell_ratio: float = 0.0  # Ratio of ~512 byte packets
    
    def to_array(self) -> List[float]:
        """Convert features to array for ML model."""
        return [
            self.flow_duration,
            self.flow_bytes_per_sec,
            self.flow_packets_per_sec,
            self.flow_iat_mean,
            self.flow_iat_std,
            self.flow_iat_max,
            self.flow_iat_min,
            self.fwd_packet_length_mean,
            self.fwd_packet_length_std,
            self.fwd_packet_length_max,
            self.fwd_packet_length_min,
            self.bwd_packet_length_mean,
            self.bwd_packet_length_std,
            float(self.total_fwd_packets),
            float(self.total_bwd_packets),
            self.packet_length_mean,
            self.packet_length_std,
            self.packet_length_variance,
            self.active_mean,
            self.idle_mean,
            self.tor_cell_ratio
        ]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'flow_duration': round(self.flow_duration, 4),
            'flow_bytes_per_sec': round(self.flow_bytes_per_sec, 2),
            'flow_packets_per_sec': round(self.flow_packets_per_sec, 4),
            'flow_iat_mean': round(self.flow_iat_mean, 6),
            'flow_iat_std': round(self.flow_iat_std, 6),
            'flow_iat_max': round(self.flow_iat_max, 6),
            'flow_iat_min': round(self.flow_iat_min, 6),
            'fwd_packet_length_mean': round(self.fwd_packet_length_mean, 2),
            'fwd_packet_length_std': round(self.fwd_packet_length_std, 2),
            'fwd_packet_length_max': round(self.fwd_packet_length_max, 2),
            'fwd_packet_length_min': round(self.fwd_packet_length_min, 2),
            'bwd_packet_length_mean': round(self.bwd_packet_length_mean, 2),
            'bwd_packet_length_std': round(self.bwd_packet_length_std, 2),
            'total_fwd_packets': self.total_fwd_packets,
            'total_bwd_packets': self.total_bwd_packets,
            'packet_length_mean': round(self.packet_length_mean, 2),
            'packet_length_std': round(self.packet_length_std, 2),
            'packet_length_variance': round(self.packet_length_variance, 2),
            'active_mean': round(self.active_mean, 6),
            'idle_mean': round(self.idle_mean, 6),
            'tor_cell_ratio': round(self.tor_cell_ratio, 3)
        }
    
    @staticmethod
    def get_feature_names() -> List[str]:
        """Get feature names for ML model."""
        return [
            'flow_duration',
            'flow_bytes_per_sec',
            'flow_packets_per_sec',
            'flow_iat_mean',
            'flow_iat_std',
            'flow_iat_max',
            'flow_iat_min',
            'fwd_packet_length_mean',
            'fwd_packet_length_std',
            'fwd_packet_length_max',
            'fwd_packet_length_min',
            'bwd_packet_length_mean',
            'bwd_packet_length_std',
            'total_fwd_packets',
            'total_bwd_packets',
            'packet_length_mean',
            'packet_length_std',
            'packet_length_variance',
            'active_mean',
            'idle_mean',
            'tor_cell_ratio'
        ]


# TOR cell sizes (~512 bytes + headers)
TOR_CELL_SIZES = range(500, 620)  # Allow some variance


class FeatureExtractor:
    """
    Extracts ML features from network flows.
    
    Based on UNB-CIC dataset approach with 21 features.
    """
    
    def __init__(self):
        """Initialize feature extractor."""
        self._idle_threshold = 1.0  # Seconds to consider as idle
    
    def _compute_iat_stats(self, timestamps: List[float]) -> Tuple[float, float, float, float]:
        """
        Compute Inter-Arrival Time statistics.
        
        Returns:
            (mean, std, min, max)
        """
        if len(timestamps) < 2:
            return 0.0, 0.0, 0.0, 0.0
        
        iats = []
        for i in range(1, len(timestamps)):
            iat = timestamps[i] - timestamps[i-1]
            if iat >= 0:
                iats.append(iat)
        
        if not iats:
            return 0.0, 0.0, 0.0, 0.0
        
        mean = statistics.mean(iats)
        std = statistics.stdev(iats) if len(iats) > 1 else 0.0
        return mean, std, min(iats), max(iats)
    
    def _compute_active_idle(self, timestamps: List[float]) -> Tuple[float, float]:
        """
        Compute active and idle time statistics.
        
        Returns:
            (active_mean, idle_mean)
        """
        if len(timestamps) < 2:
            return 0.0, 0.0
        
        active_times = []
        idle_times = []
        
        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i-1]
            if gap > self._idle_threshold:
                idle_times.append(gap)
            else:
                active_times.append(gap)
        
        active_mean = statistics.mean(active_times) if active_times else 0.0
        idle_mean = statistics.mean(idle_times) if idle_times else 0.0
        
        return active_mean, idle_mean
    
    def _compute_tor_cell_ratio(self, packet_sizes: List[int]) -> float:
        """
        Compute ratio of packets that match TOR cell size (~512 bytes).
        
        TOR cells are exactly 512 bytes, but with headers the total
        packet size is typically 514-600 bytes.
        """
        if not packet_sizes:
            return 0.0
        
        tor_cell_count = sum(1 for s in packet_sizes if s in TOR_CELL_SIZES)
        return tor_cell_count / len(packet_sizes)
    
    def extract(self, flow: NetworkFlow) -> FlowFeatures:
        """
        Extract features from a network flow.
        
        Args:
            flow: NetworkFlow object
            
        Returns:
            FlowFeatures object with 21 features
        """
        features = FlowFeatures()
        
        if not flow.packet_sizes or not flow.timestamps:
            return features
        
        # Basic flow characteristics
        features.flow_duration = flow.duration
        features.flow_bytes_per_sec = flow.bytes_per_second
        features.flow_packets_per_sec = flow.packets_per_second
        
        # IAT statistics
        iat_mean, iat_std, iat_min, iat_max = self._compute_iat_stats(flow.timestamps)
        features.flow_iat_mean = iat_mean
        features.flow_iat_std = iat_std
        features.flow_iat_min = iat_min
        features.flow_iat_max = iat_max
        
        # Packet length statistics (using all packets as forward direction estimate)
        sizes = flow.packet_sizes
        
        features.fwd_packet_length_mean = statistics.mean(sizes)
        features.fwd_packet_length_std = statistics.stdev(sizes) if len(sizes) > 1 else 0.0
        features.fwd_packet_length_max = max(sizes)
        features.fwd_packet_length_min = min(sizes)
        
        # Estimate backward packets (assume 30% of packets are responses)
        # This is a simplification since we're doing unidirectional capture
        total_packets = len(sizes)
        features.total_fwd_packets = int(total_packets * 0.7)
        features.total_bwd_packets = int(total_packets * 0.3)
        
        # Backward packet length estimates (smaller for ACKs)
        bwd_sizes = [s for s in sizes if s < 100]  # Small packets likely responses
        if bwd_sizes:
            features.bwd_packet_length_mean = statistics.mean(bwd_sizes)
            features.bwd_packet_length_std = statistics.stdev(bwd_sizes) if len(bwd_sizes) > 1 else 0.0
        
        # Overall packet length statistics
        features.packet_length_mean = flow.avg_packet_size
        features.packet_length_std = statistics.stdev(sizes) if len(sizes) > 1 else 0.0
        features.packet_length_variance = features.packet_length_std ** 2
        
        # Active/Idle times
        active_mean, idle_mean = self._compute_active_idle(flow.timestamps)
        features.active_mean = active_mean
        features.idle_mean = idle_mean
        
        # TOR-specific cell ratio
        features.tor_cell_ratio = self._compute_tor_cell_ratio(sizes)
        
        return features
    
    def extract_from_packets(self, packets: List[Dict]) -> FlowFeatures:
        """
        Extract features from a list of packet dictionaries.
        
        Args:
            packets: List of packet dicts with 'size' and 'timestamp' keys
            
        Returns:
            FlowFeatures object
        """
        features = FlowFeatures()
        
        if not packets:
            return features
        
        sizes = [p.get('size', 0) for p in packets]
        timestamps = [p.get('timestamp', 0.0) for p in packets]
        
        # Sort by timestamp
        sorted_data = sorted(zip(timestamps, sizes))
        timestamps = [t for t, _ in sorted_data]
        sizes = [s for _, s in sorted_data]
        
        if not sizes or not timestamps:
            return features
        
        # Duration
        features.flow_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0
        
        # Bytes/packets per second
        total_bytes = sum(sizes)
        if features.flow_duration > 0:
            features.flow_bytes_per_sec = total_bytes / features.flow_duration
            features.flow_packets_per_sec = len(sizes) / features.flow_duration
        
        # IAT statistics
        iat_mean, iat_std, iat_min, iat_max = self._compute_iat_stats(timestamps)
        features.flow_iat_mean = iat_mean
        features.flow_iat_std = iat_std
        features.flow_iat_min = iat_min
        features.flow_iat_max = iat_max
        
        # Packet size statistics
        features.fwd_packet_length_mean = statistics.mean(sizes)
        features.fwd_packet_length_std = statistics.stdev(sizes) if len(sizes) > 1 else 0.0
        features.fwd_packet_length_max = max(sizes)
        features.fwd_packet_length_min = min(sizes)
        
        features.packet_length_mean = features.fwd_packet_length_mean
        features.packet_length_std = features.fwd_packet_length_std
        features.packet_length_variance = features.packet_length_std ** 2
        
        features.total_fwd_packets = int(len(sizes) * 0.7)
        features.total_bwd_packets = int(len(sizes) * 0.3)
        
        # Active/Idle
        active_mean, idle_mean = self._compute_active_idle(timestamps)
        features.active_mean = active_mean
        features.idle_mean = idle_mean
        
        # TOR cell ratio
        features.tor_cell_ratio = self._compute_tor_cell_ratio(sizes)
        
        return features


# Singleton instance
_feature_extractor = None


def get_feature_extractor() -> FeatureExtractor:
    """Get singleton feature extractor instance."""
    global _feature_extractor
    if _feature_extractor is None:
        _feature_extractor = FeatureExtractor()
    return _feature_extractor
