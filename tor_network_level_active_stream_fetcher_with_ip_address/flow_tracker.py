"""
Flow Tracker Module.

Groups network packets into flows for analysis.
Tracks flow statistics and provides flow lifecycle management.
"""

import time
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from .global_listener import PacketInfo


@dataclass
class NetworkFlow:
    """
    A network flow being tracked.
    
    Groups packets by (src_ip, dst_ip, src_port, dst_port).
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    # Packet data
    packet_sizes: List[int] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    
    # State
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_active: bool = True
    
    # Classification (filled by classifier)
    is_tor: bool = False
    tor_confidence: float = 0.0
    relay_info: Optional[Dict] = None
    
    def add_packet(self, packet: PacketInfo):
        """Add a packet to this flow."""
        self.packet_sizes.append(packet.size)
        self.timestamps.append(packet.timestamp)
        
        if not self.first_seen:
            self.first_seen = packet.timestamp
        self.last_seen = packet.timestamp
    
    @property
    def packet_count(self) -> int:
        """Get total packet count."""
        return len(self.packet_sizes)
    
    @property
    def total_bytes(self) -> int:
        """Get total bytes transferred."""
        return sum(self.packet_sizes)
    
    @property
    def duration(self) -> float:
        """Get flow duration in seconds."""
        if len(self.timestamps) < 2:
            return 0.0
        return self.timestamps[-1] - self.timestamps[0]
    
    @property
    def avg_packet_size(self) -> float:
        """Get average packet size."""
        if not self.packet_sizes:
            return 0.0
        return statistics.mean(self.packet_sizes)
    
    @property
    def bytes_per_second(self) -> float:
        """Get bytes per second."""
        if self.duration <= 0:
            return 0.0
        return self.total_bytes / self.duration
    
    @property
    def packets_per_second(self) -> float:
        """Get packets per second."""
        if self.duration <= 0:
            return 0.0
        return self.packet_count / self.duration
    
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
    
    def get_iat_stats(self) -> Tuple[float, float, float, float]:
        """
        Get IAT statistics.
        
        Returns:
            (mean, std, min, max)
        """
        iats = self.get_iat_sequence()
        if not iats:
            return 0.0, 0.0, 0.0, 0.0
        
        mean = statistics.mean(iats)
        std = statistics.stdev(iats) if len(iats) > 1 else 0.0
        return mean, std, min(iats), max(iats)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        iat_mean, iat_std, iat_min, iat_max = self.get_iat_stats()
        return {
            'flow_id': self.flow_id,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'duration': round(self.duration, 3),
            'avg_packet_size': round(self.avg_packet_size, 1),
            'bytes_per_second': round(self.bytes_per_second, 1),
            'packets_per_second': round(self.packets_per_second, 2),
            'iat_mean': round(iat_mean, 6),
            'iat_std': round(iat_std, 6),
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'is_active': self.is_active,
            'is_tor': self.is_tor,
            'tor_confidence': round(self.tor_confidence, 3)
        }


class FlowTracker:
    """
    Tracks network flows from captured packets.
    
    Groups packets by flow key (src_ip, dst_ip, src_port, dst_port)
    and maintains flow state for analysis.
    """
    
    def __init__(self, 
                 flow_timeout: float = 60.0,
                 max_flows: int = 5000,
                 min_packets_for_analysis: int = 3):
        """
        Initialize flow tracker.
        
        Args:
            flow_timeout: Seconds before a flow is considered idle
            max_flows: Maximum number of flows to track
            min_packets_for_analysis: Minimum packets required for flow analysis
        """
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.min_packets_for_analysis = min_packets_for_analysis
        
        self._flows: Dict[str, NetworkFlow] = {}
        self._completed_flows: List[NetworkFlow] = []
        self._internal_ips: Dict[str, List[str]] = defaultdict(list)  # Internal IP -> [flow_ids]
    
    def _make_flow_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> str:
        """Create a unique flow key."""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    
    def process_packet(self, packet: PacketInfo) -> NetworkFlow:
        """
        Process a captured packet and update/create flow.
        
        Args:
            packet: Captured packet info
            
        Returns:
            The flow this packet belongs to
        """
        flow_key = self._make_flow_key(
            packet.src_ip, packet.dst_ip, 
            packet.src_port, packet.dst_port
        )
        
        if flow_key not in self._flows:
            # Create new flow
            if len(self._flows) >= self.max_flows:
                self._cleanup_oldest_flows()
            
            self._flows[flow_key] = NetworkFlow(
                flow_id=flow_key,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol
            )
            
            # Track internal IPs (source IPs are likely internal)
            self._internal_ips[packet.src_ip].append(flow_key)
        
        flow = self._flows[flow_key]
        flow.add_packet(packet)
        
        return flow
    
    def _cleanup_oldest_flows(self):
        """Remove oldest flows when at capacity."""
        if not self._flows:
            return
        
        # Sort by last_seen and remove oldest 10%
        sorted_flows = sorted(self._flows.items(), key=lambda x: x[1].last_seen)
        to_remove = len(sorted_flows) // 10
        
        for key, flow in sorted_flows[:to_remove]:
            flow.is_active = False
            if flow.packet_count >= self.min_packets_for_analysis:
                self._completed_flows.append(flow)
            del self._flows[key]
    
    def cleanup_idle_flows(self, current_time: Optional[float] = None) -> List[NetworkFlow]:
        """
        Move idle flows to completed list.
        
        Args:
            current_time: Current timestamp (default: now)
            
        Returns:
            List of flows that were moved to completed
        """
        if current_time is None:
            current_time = time.time()
        
        completed = []
        to_remove = []
        
        for flow_key, flow in self._flows.items():
            if current_time - flow.last_seen > self.flow_timeout:
                flow.is_active = False
                if flow.packet_count >= self.min_packets_for_analysis:
                    completed.append(flow)
                    self._completed_flows.append(flow)
                to_remove.append(flow_key)
        
        for key in to_remove:
            del self._flows[key]
        
        return completed
    
    def get_flow(self, flow_id: str) -> Optional[NetworkFlow]:
        """Get a flow by ID."""
        return self._flows.get(flow_id)
    
    def get_active_flows(self) -> List[NetworkFlow]:
        """Get all active flows."""
        return list(self._flows.values())
    
    def get_completed_flows(self) -> List[NetworkFlow]:
        """Get all completed flows."""
        return self._completed_flows.copy()
    
    def get_flows_for_ip(self, ip: str) -> List[NetworkFlow]:
        """Get all flows for an internal IP."""
        flow_ids = self._internal_ips.get(ip, [])
        flows = []
        for fid in flow_ids:
            if fid in self._flows:
                flows.append(self._flows[fid])
        return flows
    
    def get_internal_ips(self) -> List[str]:
        """Get list of detected internal IPs."""
        return list(self._internal_ips.keys())
    
    def get_tor_flows(self) -> List[NetworkFlow]:
        """Get all flows classified as TOR."""
        tor_flows = [f for f in self._flows.values() if f.is_tor]
        tor_flows.extend([f for f in self._completed_flows if f.is_tor])
        return tor_flows
    
    def get_stats(self) -> Dict:
        """Get tracker statistics."""
        tor_active = sum(1 for f in self._flows.values() if f.is_tor)
        tor_completed = sum(1 for f in self._completed_flows if f.is_tor)
        
        return {
            'active_flows': len(self._flows),
            'completed_flows': len(self._completed_flows),
            'total_flows': len(self._flows) + len(self._completed_flows),
            'tor_active_flows': tor_active,
            'tor_completed_flows': tor_completed,
            'internal_ips': len(self._internal_ips),
            'max_flows': self.max_flows,
            'flow_timeout': self.flow_timeout
        }
    
    def clear(self):
        """Clear all tracked flows."""
        self._flows.clear()
        self._completed_flows.clear()
        self._internal_ips.clear()


# Packet callback helper for GlobalListener integration
def create_flow_tracker_callback(tracker: FlowTracker):
    """
    Create a packet callback for GlobalListener that updates FlowTracker.
    
    Args:
        tracker: FlowTracker instance
        
    Returns:
        Callback function
    """
    def callback(packet: PacketInfo):
        tracker.process_packet(packet)
    
    return callback
