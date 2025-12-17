"""
Circuit Estimator Module.

Estimates the number of TOR circuits in a connection by analyzing
traffic burst patterns.

TOR multiplexes multiple circuits over a single TCP connection.
We estimate circuits by detecting bursts separated by gaps.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
import numpy as np


@dataclass
class CircuitEstimate:
    """Result of circuit estimation analysis."""
    estimated_circuits: int
    burst_count: int
    avg_burst_size: float
    avg_gap_duration: float
    confidence: float
    bursts: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'estimated_circuits': self.estimated_circuits,
            'burst_count': self.burst_count,
            'avg_burst_size': round(self.avg_burst_size, 2),
            'avg_gap_duration': round(self.avg_gap_duration, 4),
            'confidence': round(self.confidence, 3)
        }


class CircuitEstimator:
    """
    Estimates TOR circuits from traffic patterns.
    
    TOR creates new circuits approximately every 10 minutes.
    Each circuit represents a separate "virtual connection" through
    the TOR network with different routing.
    
    Detection is based on:
    1. Burst detection (clusters of packets)
    2. Gap analysis (pauses between bursts)
    3. Circuit lifetime heuristics
    """
    
    # TOR circuit default lifetime
    CIRCUIT_LIFETIME = 600  # 10 minutes
    
    # Default gap threshold for burst detection
    DEFAULT_GAP_THRESHOLD = 1.0  # 1 second
    
    def __init__(self, gap_threshold: float = 1.0):
        """
        Initialize Circuit Estimator.
        
        Args:
            gap_threshold: Minimum gap (seconds) to separate bursts
        """
        self.gap_threshold = gap_threshold
    
    def _detect_bursts(self, 
                       timestamps: List[float], 
                       sizes: Optional[List[int]] = None) -> List[Dict]:
        """
        Detect traffic bursts from timestamps.
        
        A burst is a sequence of packets with inter-arrival time
        less than gap_threshold.
        
        Args:
            timestamps: List of packet timestamps
            sizes: Optional list of packet sizes
            
        Returns:
            List of burst dictionaries with start, end, packet count, bytes
        """
        if not timestamps:
            return []
        
        sorted_ts = sorted(timestamps)
        sizes = sizes or [0] * len(timestamps)
        
        # Sort sizes by timestamp order
        if len(sizes) == len(timestamps):
            ts_size = sorted(zip(timestamps, sizes), key=lambda x: x[0])
            sorted_sizes = [s for _, s in ts_size]
        else:
            sorted_sizes = [0] * len(sorted_ts)
        
        bursts = []
        current_burst = {
            'start_time': sorted_ts[0],
            'end_time': sorted_ts[0],
            'packet_count': 1,
            'total_bytes': sorted_sizes[0],
            'packet_sizes': [sorted_sizes[0]]
        }
        
        for i in range(1, len(sorted_ts)):
            gap = sorted_ts[i] - sorted_ts[i-1]
            
            if gap < self.gap_threshold:
                # Continue current burst
                current_burst['end_time'] = sorted_ts[i]
                current_burst['packet_count'] += 1
                current_burst['total_bytes'] += sorted_sizes[i]
                current_burst['packet_sizes'].append(sorted_sizes[i])
            else:
                # End current burst, start new one
                current_burst['duration'] = current_burst['end_time'] - current_burst['start_time']
                bursts.append(current_burst)
                
                current_burst = {
                    'start_time': sorted_ts[i],
                    'end_time': sorted_ts[i],
                    'packet_count': 1,
                    'total_bytes': sorted_sizes[i],
                    'packet_sizes': [sorted_sizes[i]]
                }
        
        # Don't forget the last burst
        current_burst['duration'] = current_burst['end_time'] - current_burst['start_time']
        bursts.append(current_burst)
        
        return bursts
    
    def _analyze_gaps(self, bursts: List[Dict]) -> Tuple[List[float], float]:
        """
        Analyze gaps between bursts.
        
        Returns:
            (list of gap durations, average gap duration)
        """
        if len(bursts) < 2:
            return [], 0.0
        
        gaps = []
        for i in range(1, len(bursts)):
            gap = bursts[i]['start_time'] - bursts[i-1]['end_time']
            gaps.append(gap)
        
        avg_gap = np.mean(gaps) if gaps else 0.0
        return gaps, float(avg_gap)
    
    def _estimate_circuits_from_bursts(self, bursts: List[Dict]) -> int:
        """
        Estimate circuit count from burst analysis.
        
        Heuristics:
        - TOR circuits have request/response pattern
        - Each circuit typically shows 2+ bursts
        - Long gaps suggest new circuits
        """
        if not bursts:
            return 0
        
        # Simple heuristic: circuits ≈ bursts / 2
        # Because each circuit typically has request + response bursts
        estimated = max(1, len(bursts) // 2)
        
        # Adjust based on session duration
        if len(bursts) >= 2:
            session_duration = bursts[-1]['end_time'] - bursts[0]['start_time']
            
            # TOR creates new circuit every ~10 minutes
            time_based_estimate = max(1, int(session_duration / self.CIRCUIT_LIFETIME) + 1)
            
            # Take the maximum of both estimates
            estimated = max(estimated, time_based_estimate)
        
        return estimated
    
    def _calculate_confidence(self, 
                              bursts: List[Dict], 
                              gaps: List[float]) -> float:
        """
        Calculate confidence in circuit estimation.
        
        Higher confidence with:
        - Clear burst separation
        - Consistent burst sizes
        - Gap durations matching TOR patterns
        """
        if not bursts:
            return 0.0
        
        confidence = 0.5  # Base confidence
        
        # More bursts = more data = higher confidence
        if len(bursts) >= 5:
            confidence += 0.2
        elif len(bursts) >= 3:
            confidence += 0.1
        
        # Analyze burst size consistency
        if len(bursts) >= 2:
            sizes = [b['packet_count'] for b in bursts]
            cv = np.std(sizes) / (np.mean(sizes) + 1e-10)
            if cv < 0.5:  # Low variance = more consistent = higher confidence
                confidence += 0.15
        
        # Analyze gap patterns
        if gaps:
            # TOR typically has gaps > 100ms
            meaningful_gaps = sum(1 for g in gaps if g > 0.1)
            if meaningful_gaps / len(gaps) > 0.5:
                confidence += 0.15
        
        return min(1.0, confidence)
    
    def estimate(self, 
                 timestamps: List[float], 
                 sizes: Optional[List[int]] = None) -> CircuitEstimate:
        """
        Estimate TOR circuits from traffic pattern.
        
        Args:
            timestamps: List of packet timestamps
            sizes: Optional list of packet sizes
            
        Returns:
            CircuitEstimate with results
        """
        if not timestamps:
            return CircuitEstimate(
                estimated_circuits=0,
                burst_count=0,
                avg_burst_size=0.0,
                avg_gap_duration=0.0,
                confidence=0.0,
                bursts=[]
            )
        
        # Detect bursts
        bursts = self._detect_bursts(timestamps, sizes)
        
        # Analyze gaps
        gaps, avg_gap = self._analyze_gaps(bursts)
        
        # Estimate circuits
        estimated_circuits = self._estimate_circuits_from_bursts(bursts)
        
        # Calculate average burst size
        if bursts:
            avg_burst_size = np.mean([b['packet_count'] for b in bursts])
        else:
            avg_burst_size = 0.0
        
        # Calculate confidence
        confidence = self._calculate_confidence(bursts, gaps)
        
        # Simplify burst data for output
        simplified_bursts = [
            {
                'start_time': b['start_time'],
                'duration': b['duration'],
                'packet_count': b['packet_count'],
                'total_bytes': b['total_bytes']
            }
            for b in bursts
        ]
        
        return CircuitEstimate(
            estimated_circuits=estimated_circuits,
            burst_count=len(bursts),
            avg_burst_size=float(avg_burst_size),
            avg_gap_duration=avg_gap,
            confidence=confidence,
            bursts=simplified_bursts
        )
    
    def estimate_from_flow(self, flow: Dict) -> CircuitEstimate:
        """
        Estimate circuits from a flow dictionary.
        
        Args:
            flow: Flow dictionary with 'timestamps' and optionally 'sizes'
            
        Returns:
            CircuitEstimate
        """
        timestamps = flow.get('timestamps', [])
        sizes = flow.get('sizes', flow.get('packet_sizes', None))
        
        return self.estimate(timestamps, sizes)
