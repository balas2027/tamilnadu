"""
Origin Tracer Module.

Correlates external TOR network data with internal PCAP/network logs
to pinpoint the Probable Origin IP for detected TOR circuits.

Implements:
- Time-indexed local log correlation
- Entry Guard matching
- Composite Confidence Score (CCS) calculation
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


@dataclass
class LogicalFlow:
    """
    A logical TOR flow containing all correlation data.
    """
    flow_id: str
    
    # Entry Guard data
    entry_guard_ip: str
    entry_guard_nickname: str
    entry_guard_port: int
    
    # Middle Relay data
    middle_relay_ip: str = ""
    middle_relay_nickname: str = ""
    
    # Exit Node data
    exit_node_ip: str = ""
    exit_node_nickname: str = ""
    
    # Timing
    local_entry_time: float = 0.0  # Timestamp of first packet to guard
    circuit_id: str = ""
    purpose: str = "GENERAL"
    
    # Origin tracing result
    probable_origin_ip: str = ""
    origin_confidence: float = 0.0
    
    # Scores
    identity_score: float = 0.0
    fingerprint_score: float = 0.0
    pattern_score: float = 0.0
    composite_confidence_score: float = 0.0
    
    # Log reference
    log_reference: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'flow_id': self.flow_id,
            'probable_origin_ip': self.probable_origin_ip,
            'circuit_path': {
                'entry_guard': {
                    'ip': self.entry_guard_ip,
                    'nickname': self.entry_guard_nickname,
                    'port': self.entry_guard_port
                },
                'middle_relay': {
                    'ip': self.middle_relay_ip,
                    'nickname': self.middle_relay_nickname
                },
                'exit_node': {
                    'ip': self.exit_node_ip,
                    'nickname': self.exit_node_nickname
                }
            },
            'purpose': self.purpose,
            'local_entry_time': self.local_entry_time,
            'local_entry_time_formatted': time.strftime('%Y-%m-%d %H:%M:%S', 
                                                         time.localtime(self.local_entry_time)) if self.local_entry_time else 'N/A',
            'composite_confidence_score': round(self.composite_confidence_score, 4),
            'score_breakdown': {
                'identity_score': round(self.identity_score, 4),
                'fingerprint_score': round(self.fingerprint_score, 4),
                'pattern_score': round(self.pattern_score, 4)
            },
            'log_reference': self.log_reference
        }


@dataclass
class LocalLogEntry:
    """Entry from local network log (PCAP/NetFlow)."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    log_source: str = ""  # e.g., "PCAP: capture.pcap"


class CompositeConfidenceCalculator:
    """
    Calculates Composite Confidence Score (CCS) using weighted formula.
    
    CCS = w1 * IdentityScore + w2 * FingerprintScore + w3 * PatternScore
    
    Default weights:
    - w1 (Identity): 0.45 - TOR consensus matching
    - w2 (Fingerprint): 0.35 - JA3/TLS fingerprinting
    - w3 (Pattern): 0.20 - Traffic pattern analysis
    """
    
    DEFAULT_WEIGHTS = {
        'identity': 0.45,
        'fingerprint': 0.35,
        'pattern': 0.20
    }
    
    def __init__(self, weights: Dict[str, float] = None):
        """
        Initialize calculator with custom or default weights.
        
        Args:
            weights: Dict with 'identity', 'fingerprint', 'pattern' weights
        """
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        
        # Normalize weights to sum to 1.0
        total = sum(self.weights.values())
        if total != 1.0:
            for k in self.weights:
                self.weights[k] /= total
    
    def calculate(self, 
                  identity_score: float,
                  fingerprint_score: float,
                  pattern_score: float) -> float:
        """
        Calculate Composite Confidence Score.
        
        Args:
            identity_score: Score from TOR consensus matching (0-1)
            fingerprint_score: Score from JA3/TLS fingerprinting (0-1)
            pattern_score: Score from traffic pattern analysis (0-1)
            
        Returns:
            Composite Confidence Score (0-1)
        """
        ccs = (
            self.weights['identity'] * identity_score +
            self.weights['fingerprint'] * fingerprint_score +
            self.weights['pattern'] * pattern_score
        )
        
        return min(1.0, max(0.0, ccs))
    
    def get_weights(self) -> Dict[str, float]:
        """Get current weight configuration."""
        return self.weights.copy()


class OriginTracer:
    """
    Traces the probable Origin IP from TOR circuit data.
    
    Correlates external TOR flow data with local network logs
    by matching:
    - Timestamp (within tolerance)
    - Destination IP (Entry Guard IP)
    """
    
    # Time tolerance for matching (seconds)
    DEFAULT_TIME_TOLERANCE = 2.0
    
    def __init__(self, time_tolerance: float = 2.0):
        """
        Initialize Origin Tracer.
        
        Args:
            time_tolerance: Max time difference for matching (seconds)
        """
        self.time_tolerance = time_tolerance
        self._local_logs: List[LocalLogEntry] = []
        self._time_index: Dict[int, List[LocalLogEntry]] = defaultdict(list)
        self._ccs_calculator = CompositeConfidenceCalculator()
    
    def load_local_logs(self, logs: List[LocalLogEntry]):
        """
        Load local network logs and build time index.
        
        Args:
            logs: List of LocalLogEntry objects
        """
        self._local_logs = logs
        self._build_time_index()
    
    def load_from_packets(self, packets: List[Dict], log_source: str = ""):
        """
        Load local logs from packet dictionaries.
        
        Args:
            packets: List of packet dicts with src, dst, time, size
            log_source: Reference to log source (e.g., PCAP filename)
        """
        logs = []
        for pkt in packets:
            entry = LocalLogEntry(
                timestamp=pkt.get('time', pkt.get('timestamp', 0)),
                src_ip=pkt.get('src', pkt.get('src_ip', '')),
                dst_ip=pkt.get('dst', pkt.get('dst_ip', '')),
                src_port=pkt.get('src_port', 0),
                dst_port=pkt.get('dst_port', 0),
                protocol=pkt.get('proto', 'TCP'),
                size=pkt.get('size', 0),
                log_source=log_source
            )
            logs.append(entry)
        
        self.load_local_logs(logs)
    
    def _build_time_index(self):
        """Build time-indexed lookup table for fast correlation."""
        self._time_index.clear()
        
        for log in self._local_logs:
            # Index by second (floored timestamp)
            time_key = int(log.timestamp)
            self._time_index[time_key].append(log)
    
    def trace_origin(self, flow: LogicalFlow) -> Tuple[str, float, str]:
        """
        Trace the probable origin IP for a logical flow.
        
        Searches local logs for packets matching:
        - Timestamp ≈ flow.local_entry_time (within tolerance)
        - Destination IP = flow.entry_guard_ip
        
        Args:
            flow: LogicalFlow with Entry Guard data
            
        Returns:
            Tuple of (probable_origin_ip, confidence, log_reference)
        """
        if not self._local_logs:
            return ("", 0.0, "No local logs loaded")
        
        entry_time = flow.local_entry_time
        entry_guard_ip = flow.entry_guard_ip
        
        # Search time window
        start_sec = int(entry_time - self.time_tolerance)
        end_sec = int(entry_time + self.time_tolerance) + 1
        
        candidates = []
        
        for time_key in range(start_sec, end_sec):
            if time_key in self._time_index:
                for log in self._time_index[time_key]:
                    # Check if destination matches Entry Guard
                    if log.dst_ip == entry_guard_ip:
                        time_diff = abs(log.timestamp - entry_time)
                        if time_diff <= self.time_tolerance:
                            candidates.append((log, time_diff))
        
        if not candidates:
            # No exact match - try broader search
            return self._fuzzy_trace(flow)
        
        # Sort by time difference (closest first)
        candidates.sort(key=lambda x: x[1])
        
        best_match, time_diff = candidates[0]
        
        # Calculate confidence based on time proximity
        confidence = 1.0 - (time_diff / self.time_tolerance)
        confidence = max(0.5, confidence)  # Minimum 50% if match found
        
        log_ref = f"{best_match.log_source}, timestamp: {best_match.timestamp:.6f}"
        
        return (best_match.src_ip, confidence, log_ref)
    
    def _fuzzy_trace(self, flow: LogicalFlow) -> Tuple[str, float, str]:
        """
        Fuzzy trace when exact match not found.
        
        Looks for any traffic to the Entry Guard IP.
        """
        entry_guard_ip = flow.entry_guard_ip
        
        candidates = []
        for log in self._local_logs:
            if log.dst_ip == entry_guard_ip:
                candidates.append(log)
        
        if not candidates:
            return ("", 0.0, "No matching packets found")
        
        # Return most common source IP
        src_counts = defaultdict(int)
        for log in candidates:
            src_counts[log.src_ip] += 1
        
        best_src = max(src_counts, key=src_counts.get)
        confidence = min(0.5, src_counts[best_src] / len(candidates))
        
        return (best_src, confidence, "Fuzzy match - no exact timestamp correlation")
    
    def analyze_flow(self, flow: LogicalFlow) -> LogicalFlow:
        """
        Complete analysis of a logical flow.
        
        Traces origin and calculates Composite Confidence Score.
        
        Args:
            flow: LogicalFlow to analyze
            
        Returns:
            Updated LogicalFlow with origin and scores
        """
        # Trace origin
        origin_ip, origin_conf, log_ref = self.trace_origin(flow)
        
        flow.probable_origin_ip = origin_ip
        flow.origin_confidence = origin_conf
        flow.log_reference = log_ref
        
        # Calculate Composite Confidence Score
        flow.composite_confidence_score = self._ccs_calculator.calculate(
            identity_score=flow.identity_score,
            fingerprint_score=flow.fingerprint_score,
            pattern_score=flow.pattern_score
        )
        
        return flow
    
    def get_local_origin_ips(self) -> List[str]:
        """Get unique local origin IPs from logs."""
        return list(set(log.src_ip for log in self._local_logs))
    
    def get_log_stats(self) -> Dict:
        """Get statistics about loaded logs."""
        if not self._local_logs:
            return {'loaded': False, 'count': 0}
        
        timestamps = [log.timestamp for log in self._local_logs]
        
        return {
            'loaded': True,
            'count': len(self._local_logs),
            'unique_sources': len(set(log.src_ip for log in self._local_logs)),
            'unique_destinations': len(set(log.dst_ip for log in self._local_logs)),
            'time_range_start': min(timestamps),
            'time_range_end': max(timestamps),
            'duration': max(timestamps) - min(timestamps)
        }


# Singleton instance
_tracer_instance: Optional[OriginTracer] = None


def get_origin_tracer() -> OriginTracer:
    """Get singleton Origin Tracer instance."""
    global _tracer_instance
    if _tracer_instance is None:
        _tracer_instance = OriginTracer()
    return _tracer_instance
