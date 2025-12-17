"""
Helper functions for TOR traffic analysis.

Provides utility functions for IP matching, entropy calculation,
and traffic pattern analysis.
"""

import math
from typing import List, Optional
from collections import Counter

from .constants import (
    TOR_RELAY_PREFIXES,
    TOR_PORTS,
    TOR_CELL_SIZES,
    TOR_PACKET_SIZE_RANGE
)


def is_tor_relay(ip: str) -> bool:
    """
    Check if an IP address belongs to a known TOR relay.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if IP matches known TOR relay prefixes
    """
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in TOR_RELAY_PREFIXES)


def is_tor_port(port: int) -> bool:
    """
    Check if a port is commonly used by TOR.
    
    Args:
        port: Port number to check
        
    Returns:
        True if port is a known TOR port
    """
    return port in TOR_PORTS


def is_tor_cell_size(size: int) -> bool:
    """
    Check if packet size matches TOR cell size pattern.
    
    TOR uses fixed 512-byte cells, but with various protocol
    headers the observed sizes cluster around specific values.
    
    Args:
        size: Packet size in bytes
        
    Returns:
        True if size matches TOR cell pattern
    """
    # Exact match
    if size in TOR_CELL_SIZES:
        return True
    
    # Within TOR packet size range
    min_size, max_size = TOR_PACKET_SIZE_RANGE
    return min_size <= size <= max_size


def calculate_entropy(values: List[int]) -> float:
    """
    Calculate Shannon entropy of a value distribution.
    
    Used for analyzing packet size distributions. TOR traffic
    has lower entropy due to fixed cell sizes.
    
    Args:
        values: List of values (e.g., packet sizes)
        
    Returns:
        Shannon entropy value
    """
    if not values:
        return 0.0
    
    # Count frequencies
    counter = Counter(values)
    total = len(values)
    
    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            prob = count / total
            entropy -= prob * math.log2(prob)
    
    return entropy


def check_iat_pattern(iat_mean: float, iat_std: float) -> bool:
    """
    Check if Inter-Arrival Time pattern matches TOR traffic.
    
    TOR traffic typically has:
    - Higher latency (due to 3 hops)
    - Lower variance (consistent relay processing)
    
    Args:
        iat_mean: Mean inter-arrival time in seconds
        iat_std: Standard deviation of inter-arrival time
        
    Returns:
        True if IAT pattern is consistent with TOR
    """
    if iat_mean <= 0:
        return False
    
    # Coefficient of variation
    cv = iat_std / iat_mean
    
    # TOR typically has CV < 0.5 (low variance)
    # and mean IAT between 0.01 and 0.5 seconds
    return cv < 0.5 and 0.005 < iat_mean < 1.0


def calculate_burst_count(timestamps: List[float], gap_threshold: float = 1.0) -> int:
    """
    Count traffic bursts based on inter-packet gaps.
    
    A burst is defined as a sequence of packets separated
    by less than gap_threshold seconds.
    
    Args:
        timestamps: Sorted list of packet timestamps
        gap_threshold: Minimum gap to separate bursts (seconds)
        
    Returns:
        Number of detected bursts
    """
    if not timestamps or len(timestamps) < 2:
        return 1
    
    burst_count = 1
    sorted_ts = sorted(timestamps)
    
    for i in range(1, len(sorted_ts)):
        if sorted_ts[i] - sorted_ts[i-1] > gap_threshold:
            burst_count += 1
    
    return burst_count


def estimate_circuits(timestamps: List[float], window: float = 1.0) -> int:
    """
    Estimate number of TOR circuits from traffic pattern.
    
    TOR multiplexes multiple circuits over a single TCP connection.
    We estimate circuits by counting bursts and applying heuristics.
    
    Args:
        timestamps: List of packet timestamps
        window: Time window for burst detection (seconds)
        
    Returns:
        Estimated number of circuits
    """
    burst_count = calculate_burst_count(timestamps, window)
    
    # Heuristic: circuits ≈ bursts / 2
    # (each circuit typically has request + response bursts)
    return max(1, burst_count // 2)


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def calculate_packets_per_second(packet_count: int, duration: float) -> float:
    """Calculate packet rate."""
    if duration <= 0:
        return 0.0
    return packet_count / duration


def calculate_bytes_per_second(total_bytes: int, duration: float) -> float:
    """Calculate throughput."""
    if duration <= 0:
        return 0.0
    return total_bytes / duration
