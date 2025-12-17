"""
Correlation Attack Module.

Implements traffic correlation attacks against TOR circuits:
- Timing Correlation Attack (Entry-Exit timing analysis)
- Volume Correlation Attack (Packet size/count matching)
- Statistical Significance Testing

These techniques can de-anonymize TOR traffic by correlating
observations at Entry Guards with observations at Exit Nodes.
"""

import math
import time
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import statistics


@dataclass
class TrafficObservation:
    """Traffic observation at a network point."""
    observer_id: str  # "entry" or "exit"
    timestamp: float
    packet_size: int
    direction: int  # 1=outgoing, -1=incoming
    flow_id: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'observer': self.observer_id,
            'timestamp': self.timestamp,
            'size': self.packet_size,
            'direction': self.direction,
            'flow_id': self.flow_id
        }


@dataclass
class CorrelationResult:
    """Result of a correlation attack."""
    attack_type: str
    entry_flow_id: str
    exit_flow_id: str
    correlation_score: float  # 0-1, higher = more correlated
    confidence: float
    is_match: bool
    evidence: List[str]
    statistical_significance: float  # p-value
    
    def to_dict(self) -> Dict:
        return {
            'attack_type': self.attack_type,
            'entry_flow': self.entry_flow_id,
            'exit_flow': self.exit_flow_id,
            'correlation_score': round(self.correlation_score, 4),
            'confidence': round(self.confidence, 4),
            'is_match': self.is_match,
            'evidence': self.evidence,
            'p_value': round(self.statistical_significance, 6)
        }


class TimingCorrelationAttack:
    """
    Timing Correlation Attack.
    
    Correlates traffic at Entry Guard with traffic at Exit Node
    based on Inter-Arrival Time (IAT) patterns.
    
    Technique: Compare IAT sequences using cross-correlation
    to find matching traffic patterns.
    """
    
    # TOR adds ~300-500ms latency per hop (3 hops = ~1-1.5s total)
    TOR_LATENCY_MIN = 0.3
    TOR_LATENCY_MAX = 2.0
    
    def __init__(self, latency_tolerance: float = 2.0):
        """
        Initialize timing attack.
        
        Args:
            latency_tolerance: Expected TOR circuit latency (seconds)
        """
        self.latency_tolerance = latency_tolerance
    
    def extract_iat_sequence(self, observations: List[TrafficObservation]) -> List[float]:
        """Extract IAT sequence from observations."""
        if len(observations) < 2:
            return []
        
        sorted_obs = sorted(observations, key=lambda x: x.timestamp)
        iats = []
        
        for i in range(1, len(sorted_obs)):
            iat = sorted_obs[i].timestamp - sorted_obs[i-1].timestamp
            if iat > 0:
                iats.append(iat)
        
        return iats
    
    def cross_correlate(self, seq1: List[float], seq2: List[float]) -> float:
        """
        Compute normalized cross-correlation between two sequences.
        
        Returns correlation coefficient (-1 to 1).
        """
        if len(seq1) < 3 or len(seq2) < 3:
            return 0.0
        
        # Truncate to same length
        min_len = min(len(seq1), len(seq2))
        s1 = seq1[:min_len]
        s2 = seq2[:min_len]
        
        mean1 = statistics.mean(s1)
        mean2 = statistics.mean(s2)
        std1 = statistics.stdev(s1) if len(s1) > 1 else 1
        std2 = statistics.stdev(s2) if len(s2) > 1 else 1
        
        if std1 == 0 or std2 == 0:
            return 0.0
        
        # Pearson correlation
        correlation = sum((s1[i] - mean1) * (s2[i] - mean2) for i in range(min_len))
        correlation /= (min_len * std1 * std2)
        
        return correlation
    
    def attack(self, 
               entry_observations: List[TrafficObservation],
               exit_observations: List[TrafficObservation],
               time_offset: float = None) -> CorrelationResult:
        """
        Perform timing correlation attack.
        
        Args:
            entry_observations: Traffic seen at Entry Guard
            exit_observations: Traffic seen at Exit Node
            time_offset: Expected time offset (TOR latency)
            
        Returns:
            CorrelationResult with match determination
        """
        evidence = []
        
        # Extract IAT sequences
        entry_iats = self.extract_iat_sequence(entry_observations)
        exit_iats = self.extract_iat_sequence(exit_observations)
        
        if len(entry_iats) < 3 or len(exit_iats) < 3:
            return CorrelationResult(
                attack_type="TIMING",
                entry_flow_id=entry_observations[0].flow_id if entry_observations else "",
                exit_flow_id=exit_observations[0].flow_id if exit_observations else "",
                correlation_score=0.0,
                confidence=0.0,
                is_match=False,
                evidence=["Insufficient IAT data for correlation"],
                statistical_significance=1.0
            )
        
        # Cross-correlate IAT patterns
        correlation = self.cross_correlate(entry_iats, exit_iats)
        evidence.append(f"IAT correlation coefficient: {correlation:.4f}")
        
        # Check time offset consistency
        if time_offset is None:
            # Estimate offset from first packets
            entry_start = min(o.timestamp for o in entry_observations)
            exit_start = min(o.timestamp for o in exit_observations)
            time_offset = exit_start - entry_start
        
        offset_valid = self.TOR_LATENCY_MIN <= time_offset <= self.TOR_LATENCY_MAX
        evidence.append(f"Time offset: {time_offset:.3f}s (valid: {offset_valid})")
        
        # Calculate confidence
        correlation_score = max(0, correlation)  # Only positive correlation
        
        # Boost if offset is within expected TOR range
        if offset_valid:
            correlation_score = min(1.0, correlation_score * 1.2)
            evidence.append("Time offset consistent with TOR latency")
        
        # Statistical significance (simplified)
        n = min(len(entry_iats), len(exit_iats))
        t_stat = correlation * math.sqrt((n - 2) / (1 - correlation**2 + 0.001))
        p_value = max(0.001, 1 - min(0.999, abs(t_stat) / 10))
        
        evidence.append(f"Statistical significance: p={p_value:.4f}")
        
        # Determine match
        is_match = correlation_score >= 0.6 and p_value < 0.05
        
        return CorrelationResult(
            attack_type="TIMING",
            entry_flow_id=entry_observations[0].flow_id if entry_observations else "",
            exit_flow_id=exit_observations[0].flow_id if exit_observations else "",
            correlation_score=correlation_score,
            confidence=correlation_score * (1 - p_value),
            is_match=is_match,
            evidence=evidence,
            statistical_significance=p_value
        )


class VolumeCorrelationAttack:
    """
    Volume Correlation Attack.
    
    Correlates traffic based on packet counts and sizes
    observed at Entry and Exit points.
    """
    
    def __init__(self, size_tolerance: float = 0.1):
        """
        Initialize volume attack.
        
        Args:
            size_tolerance: Allowed size variation (10% default)
        """
        self.size_tolerance = size_tolerance
    
    def extract_volume_features(self, observations: List[TrafficObservation]) -> Dict:
        """Extract volume-based features."""
        if not observations:
            return {'count': 0, 'total_bytes': 0, 'avg_size': 0, 'sizes': []}
        
        sizes = [o.packet_size for o in observations]
        
        return {
            'count': len(observations),
            'total_bytes': sum(sizes),
            'avg_size': statistics.mean(sizes),
            'std_size': statistics.stdev(sizes) if len(sizes) > 1 else 0,
            'sizes': sizes
        }
    
    def attack(self,
               entry_observations: List[TrafficObservation],
               exit_observations: List[TrafficObservation]) -> CorrelationResult:
        """
        Perform volume correlation attack.
        
        Args:
            entry_observations: Traffic at Entry Guard
            exit_observations: Traffic at Exit Node
            
        Returns:
            CorrelationResult
        """
        evidence = []
        
        entry_features = self.extract_volume_features(entry_observations)
        exit_features = self.extract_volume_features(exit_observations)
        
        if entry_features['count'] == 0 or exit_features['count'] == 0:
            return CorrelationResult(
                attack_type="VOLUME",
                entry_flow_id="",
                exit_flow_id="",
                correlation_score=0.0,
                confidence=0.0,
                is_match=False,
                evidence=["No traffic data"],
                statistical_significance=1.0
            )
        
        # Compare packet counts
        count_ratio = min(entry_features['count'], exit_features['count']) / max(entry_features['count'], exit_features['count'])
        evidence.append(f"Packet count ratio: {count_ratio:.3f}")
        
        # Compare total bytes (accounting for TOR overhead ~512 bytes/cell)
        # TOR adds overhead, so exit should be slightly smaller
        bytes_ratio = exit_features['total_bytes'] / (entry_features['total_bytes'] + 1)
        evidence.append(f"Byte ratio (exit/entry): {bytes_ratio:.3f}")
        
        # Compare average sizes
        if entry_features['avg_size'] > 0:
            size_diff = abs(entry_features['avg_size'] - exit_features['avg_size']) / entry_features['avg_size']
            evidence.append(f"Avg size difference: {size_diff:.1%}")
        else:
            size_diff = 1.0
        
        # Calculate correlation score
        correlation_score = (count_ratio * 0.4 + (1 - min(1, size_diff)) * 0.3 + bytes_ratio * 0.3)
        correlation_score = min(1.0, max(0.0, correlation_score))
        
        # Simplified statistical test
        p_value = max(0.001, 1 - correlation_score)
        
        is_match = correlation_score >= 0.7
        
        return CorrelationResult(
            attack_type="VOLUME",
            entry_flow_id=entry_observations[0].flow_id if entry_observations else "",
            exit_flow_id=exit_observations[0].flow_id if exit_observations else "",
            correlation_score=correlation_score,
            confidence=correlation_score,
            is_match=is_match,
            evidence=evidence,
            statistical_significance=p_value
        )


class CorrelationAttackEngine:
    """
    Combined Correlation Attack Engine.
    
    Runs multiple correlation attacks and fuses results
    for higher accuracy de-anonymization.
    """
    
    def __init__(self):
        """Initialize attack engine."""
        self.timing_attack = TimingCorrelationAttack()
        self.volume_attack = VolumeCorrelationAttack()
        self._attack_history: List[CorrelationResult] = []
    
    def run_full_attack(self,
                        entry_observations: List[TrafficObservation],
                        exit_observations: List[TrafficObservation]) -> Dict:
        """
        Run all correlation attacks and fuse results.
        
        Args:
            entry_observations: Traffic at Entry Guard
            exit_observations: Traffic at Exit Node
            
        Returns:
            Combined attack results
        """
        # Run individual attacks
        timing_result = self.timing_attack.attack(entry_observations, exit_observations)
        volume_result = self.volume_attack.attack(entry_observations, exit_observations)
        
        # Store history
        self._attack_history.extend([timing_result, volume_result])
        
        # Fuse results (weighted combination)
        combined_score = (
            timing_result.correlation_score * 0.6 +
            volume_result.correlation_score * 0.4
        )
        
        combined_confidence = (
            timing_result.confidence * 0.6 +
            volume_result.confidence * 0.4
        )
        
        # Combined match determination
        is_match = combined_score >= 0.65 or (timing_result.is_match and volume_result.is_match)
        
        return {
            'combined_score': round(combined_score, 4),
            'combined_confidence': round(combined_confidence, 4),
            'is_correlation_match': is_match,
            'timing_attack': timing_result.to_dict(),
            'volume_attack': volume_result.to_dict(),
            'conclusion': self._generate_conclusion(is_match, combined_score, timing_result, volume_result)
        }
    
    def _generate_conclusion(self, is_match: bool, score: float, 
                            timing: CorrelationResult, volume: CorrelationResult) -> str:
        """Generate human-readable conclusion."""
        if is_match and score >= 0.8:
            return f"HIGH CONFIDENCE: Entry and Exit traffic are STRONGLY CORRELATED. " \
                   f"Same user identified with {score:.1%} confidence."
        elif is_match:
            return f"MODERATE CONFIDENCE: Traffic correlation detected ({score:.1%}). " \
                   f"Probable same origin - recommend further analysis."
        elif score >= 0.4:
            return f"LOW CONFIDENCE: Weak correlation detected ({score:.1%}). " \
                   f"Insufficient evidence for de-anonymization."
        else:
            return f"NO CORRELATION: Traffic appears unrelated ({score:.1%}). " \
                   f"Different users or effective anonymization."
    
    def simulate_attack_demo(self, correlation_level: str = "high") -> Dict:
        """
        Generate simulated attack data for demonstration.
        
        Args:
            correlation_level: "high", "medium", "low", or "none"
            
        Returns:
            Attack results with simulated data
        """
        import random
        
        base_time = time.time()
        
        # Generate entry observations
        entry_obs = []
        for i in range(50):
            entry_obs.append(TrafficObservation(
                observer_id="entry",
                timestamp=base_time + i * 0.1 + random.uniform(0, 0.02),
                packet_size=random.randint(400, 600),
                direction=1 if i % 3 == 0 else -1,
                flow_id="ENTRY-FLOW-001"
            ))
        
        # Generate exit observations based on correlation level
        exit_obs = []
        tor_latency = 0.8  # 800ms TOR latency
        
        for i, entry in enumerate(entry_obs):
            if correlation_level == "high":
                # High correlation: similar timing/sizes
                noise = random.uniform(-0.01, 0.01)
                size_noise = random.randint(-20, 20)
            elif correlation_level == "medium":
                noise = random.uniform(-0.05, 0.05)
                size_noise = random.randint(-100, 100)
            elif correlation_level == "low":
                noise = random.uniform(-0.2, 0.2)
                size_noise = random.randint(-200, 200)
            else:  # none
                noise = random.uniform(-1, 1)
                size_noise = random.randint(-500, 500)
            
            exit_obs.append(TrafficObservation(
                observer_id="exit",
                timestamp=entry.timestamp + tor_latency + noise,
                packet_size=max(100, entry.packet_size + size_noise),
                direction=entry.direction,
                flow_id="EXIT-FLOW-001"
            ))
        
        # Run attack
        return self.run_full_attack(entry_obs, exit_obs)
    
    def get_attack_history(self) -> List[Dict]:
        """Get history of all attacks."""
        return [r.to_dict() for r in self._attack_history]
    
    def clear_history(self):
        """Clear attack history."""
        self._attack_history.clear()


# Convenience function
def get_correlation_engine() -> CorrelationAttackEngine:
    """Get correlation attack engine instance."""
    return CorrelationAttackEngine()
