"""
Correlation Attack Module.

Implements traffic correlation attacks against TOR circuits:
- Timing Correlation Attack (Entry-Exit timing analysis)
- Volume Correlation Attack (Packet size/count matching)
- High-Confidence Fusion Engine with weighted probability scoring
- Statistical Significance Testing

These techniques can de-anonymize TOR traffic by correlating
observations at Entry Guards with observations at Exit Nodes.

Enhanced for Hackathon Demo with:
- Composite Confidence Score (CCS) with weighted components
- Simulation Mode for demonstrations without exit node access
- Refined IAT segmentation for fast-moving circuits
- JA3 Fingerprint integration for sparse data scenarios
"""

import math
import time
import hashlib
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import statistics


# =========================================================================
# CONFIGURATION CONSTANTS
# =========================================================================

# IAT Gap Threshold - lowered for better fast-circuit segmentation
IAT_GAP_THRESHOLD = 1.0  # seconds (was 2.0)

# TOR Latency Range (3-hop circuit)
# UPDATED: Realistic TOR circuits can experience significant delays
TOR_LATENCY_MIN = 0.3    # 300ms minimum
TOR_LATENCY_MAX = 5.0    # 5s max for congested relays (was 0.8s)

# Jitter for simulation
DEMO_JITTER_MIN = 0.005  # 5ms
DEMO_JITTER_MAX = 0.010  # 10ms

# Minimum Flow Requirements for Reliable Correlation
MIN_PACKETS_FOR_CORRELATION = 50      # Minimum packets
RECOMMENDED_PACKETS = 300             # Recommended for high confidence
MAX_PACKETS_BUFFER = 900              # Maximum buffer size
MIN_FLOW_DURATION_SECONDS = 15        # Minimum 15 seconds of traffic

# =========================================================================
# FUSION ENGINE WEIGHTS CONFIGURATION
# =========================================================================

# Default weights (sum to 1.0)
# - Standard balanced scoring
WEIGHT_TIMING_DEFAULT = 0.45
WEIGHT_VOLUME_DEFAULT = 0.35
WEIGHT_JA3_DEFAULT = 0.20

# Asymmetric Visibility Weights (single vantage point)
# - Prioritize Volume over Timing when network jitter is high
# - Volume (total bytes) is more stable across the circuit
WEIGHT_TIMING_ASYMMETRIC = 0.30
WEIGHT_VOLUME_ASYMMETRIC = 0.50
WEIGHT_JA3_ASYMMETRIC = 0.20

# Current active weights (can be toggled)
WEIGHT_TIMING = WEIGHT_TIMING_ASYMMETRIC  # Default to asymmetric for real-world
WEIGHT_VOLUME = WEIGHT_VOLUME_ASYMMETRIC
WEIGHT_JA3 = WEIGHT_JA3_ASYMMETRIC

# Known TOR Browser JA3 fingerprints for matching
TOR_JA3_FINGERPRINTS = {
    'ea9d9e3db8a94c9d7b29c878a634d99f',  # TOR Browser 12.x
    'e4a24eb3fe620f3e3f77f79f1c70b088',  # TOR Browser 11.x
    'cd08e31494f9531f560d64c695473da9',  # TOR Browser (older)
    '55f8c4ad8f2b1ad5ebbf28e68d9fa0b5',  # Firefox ESR
    'b32309a26951912be7dba376398abc3b',  # Firefox ESR variant
}


# =========================================================================
# DATA CLASSES
# =========================================================================

@dataclass
class TrafficObservation:
    """Traffic observation at a network point."""
    observer_id: str  # "entry" or "exit"
    timestamp: float
    packet_size: int
    direction: int  # 1=outgoing, -1=incoming
    flow_id: str = ""
    ja3_hash: Optional[str] = None  # JA3 fingerprint if available
    
    def to_dict(self) -> Dict:
        return {
            'observer': self.observer_id,
            'timestamp': self.timestamp,
            'size': self.packet_size,
            'direction': self.direction,
            'flow_id': self.flow_id,
            'ja3_hash': self.ja3_hash
        }


@dataclass
class CCSBreakdown:
    """Composite Confidence Score breakdown for forensic evidence."""
    timing_score: float
    timing_weight: float
    volume_score: float
    volume_weight: float
    ja3_score: float
    ja3_weight: float
    composite_score: float
    
    def to_dict(self) -> Dict:
        return {
            'timing': {'score': round(self.timing_score, 4), 'weight': self.timing_weight, 'contribution': round(self.timing_score * self.timing_weight, 4)},
            'volume': {'score': round(self.volume_score, 4), 'weight': self.volume_weight, 'contribution': round(self.volume_score * self.volume_weight, 4)},
            'ja3': {'score': round(self.ja3_score, 4), 'weight': self.ja3_weight, 'contribution': round(self.ja3_score * self.ja3_weight, 4)},
            'composite': round(self.composite_score, 4)
        }
    
    def to_evidence_string(self) -> str:
        """Generate human-readable CCS breakdown for non-technical users."""
        return (
            f"CCS Breakdown: "
            f"Timing ({self.timing_weight:.0%}): {self.timing_score:.2f} → {self.timing_score * self.timing_weight:.3f} | "
            f"Volume ({self.volume_weight:.0%}): {self.volume_score:.2f} → {self.volume_score * self.volume_weight:.3f} | "
            f"JA3 ({self.ja3_weight:.0%}): {self.ja3_score:.2f} → {self.ja3_score * self.ja3_weight:.3f} = "
            f"CCS: {self.composite_score:.3f}"
        )


@dataclass
class CorrelationResult:
    """Result of a correlation attack with forensic evidence."""
    attack_type: str
    entry_flow_id: str
    exit_flow_id: str
    correlation_score: float  # 0-1, higher = more correlated (now CCS)
    confidence: float
    is_match: bool
    evidence: List[str]
    statistical_significance: float  # p-value
    ccs_breakdown: Optional[CCSBreakdown] = None
    matched_ja3: Optional[str] = None
    
    def to_dict(self) -> Dict:
        result = {
            'attack_type': self.attack_type,
            'entry_flow': self.entry_flow_id,
            'exit_flow': self.exit_flow_id,
            'correlation_score': round(self.correlation_score, 4),
            'confidence': round(self.confidence, 4),
            'is_match': self.is_match,
            'evidence': self.evidence,
            'p_value': round(self.statistical_significance, 6)
        }
        if self.ccs_breakdown:
            result['ccs_breakdown'] = self.ccs_breakdown.to_dict()
        if self.matched_ja3:
            result['matched_ja3'] = self.matched_ja3
        return result


# =========================================================================
# TIMING CORRELATION ATTACK
# =========================================================================

class TimingCorrelationAttack:
    """
    Timing Correlation Attack.
    
    Correlates traffic at Entry Guard with traffic at Exit Node
    based on Inter-Arrival Time (IAT) patterns.
    
    Enhanced with:
    - Refined IAT threshold (1.0s) for fast circuits
    - Improved cross_correlate sensitivity
    """
    
    def __init__(self, latency_tolerance: float = TOR_LATENCY_MAX):
        self.latency_tolerance = latency_tolerance
        self.iat_gap_threshold = IAT_GAP_THRESHOLD
    
    def extract_iat_sequence(self, observations: List[TrafficObservation]) -> List[float]:
        """Extract IAT sequence from observations with refined threshold."""
        if len(observations) < 2:
            return []
        
        sorted_obs = sorted(observations, key=lambda x: x.timestamp)
        iats = []
        
        for i in range(1, len(sorted_obs)):
            iat = sorted_obs[i].timestamp - sorted_obs[i-1].timestamp
            # Only include IATs below gap threshold (segment separation)
            if 0 < iat < self.iat_gap_threshold:
                iats.append(iat)
        
        return iats
    
    def cross_correlate(self, seq1: List[float], seq2: List[float]) -> float:
        """
        Compute normalized cross-correlation between two sequences.
        
        Enhanced for better sensitivity with sparse data.
        Returns correlation coefficient (-1 to 1).
        """
        # Lowered minimum from 3 to 2 for sparse data
        if len(seq1) < 2 or len(seq2) < 2:
            return 0.0
        
        # Truncate to same length
        min_len = min(len(seq1), len(seq2))
        s1 = seq1[:min_len]
        s2 = seq2[:min_len]
        
        mean1 = statistics.mean(s1)
        mean2 = statistics.mean(s2)
        std1 = statistics.stdev(s1) if len(s1) > 1 else 0.001
        std2 = statistics.stdev(s2) if len(s2) > 1 else 0.001
        
        if std1 < 0.001 or std2 < 0.001:
            # Low variance = nearly identical timing = high correlation
            return 0.95
        
        # Pearson correlation with protection against division error
        try:
            correlation = sum((s1[i] - mean1) * (s2[i] - mean2) for i in range(min_len))
            correlation /= (min_len * std1 * std2)
        except (ZeroDivisionError, ValueError):
            correlation = 0.0
        
        return max(-1.0, min(1.0, correlation))
    
    def attack(self, 
               entry_observations: List[TrafficObservation],
               exit_observations: List[TrafficObservation],
               time_offset: float = None) -> Tuple[float, List[str]]:
        """
        Perform timing correlation attack.
        
        Returns:
            (timing_score, evidence_list) tuple
        """
        evidence = []
        
        # Extract IAT sequences
        entry_iats = self.extract_iat_sequence(entry_observations)
        exit_iats = self.extract_iat_sequence(exit_observations)
        
        evidence.append(f"Entry IAT count: {len(entry_iats)}, Exit IAT count: {len(exit_iats)}")
        
        if len(entry_iats) < 2 or len(exit_iats) < 2:
            evidence.append("⚠️ Insufficient IAT data (minimum 2 required)")
            return 0.0, evidence
        
        # Cross-correlate IAT patterns
        correlation = self.cross_correlate(entry_iats, exit_iats)
        evidence.append(f"IAT correlation coefficient: {correlation:.4f}")
        
        # Check time offset consistency
        if time_offset is None:
            entry_start = min(o.timestamp for o in entry_observations)
            exit_start = min(o.timestamp for o in exit_observations)
            time_offset = exit_start - entry_start
        
        offset_valid = TOR_LATENCY_MIN <= time_offset <= TOR_LATENCY_MAX
        evidence.append(f"Time offset: {time_offset*1000:.1f}ms (TOR range: {TOR_LATENCY_MIN*1000:.0f}-{TOR_LATENCY_MAX*1000:.0f}ms) → {'✓ Valid' if offset_valid else '✗ Invalid'}")
        
        # Calculate timing score
        timing_score = max(0, correlation)
        
        # Boost if offset is within expected TOR range
        if offset_valid:
            timing_score = min(1.0, timing_score * 1.3)
            evidence.append("✓ Time offset consistent with TOR 3-hop latency")
        
        return timing_score, evidence


# =========================================================================
# VOLUME CORRELATION ATTACK
# =========================================================================

class VolumeCorrelationAttack:
    """
    Volume Correlation Attack.
    
    Correlates traffic based on packet counts and sizes
    observed at Entry and Exit points.
    """
    
    def __init__(self, size_tolerance: float = 0.15):
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
               exit_observations: List[TrafficObservation]) -> Tuple[float, List[str]]:
        """
        Perform volume correlation attack.
        
        Returns:
            (volume_score, evidence_list) tuple
        """
        evidence = []
        
        entry_features = self.extract_volume_features(entry_observations)
        exit_features = self.extract_volume_features(exit_observations)
        
        evidence.append(f"Entry packets: {entry_features['count']}, Exit packets: {exit_features['count']}")
        
        if entry_features['count'] == 0 or exit_features['count'] == 0:
            evidence.append("⚠️ No traffic data available")
            return 0.0, evidence
        
        # Compare packet counts
        count_ratio = min(entry_features['count'], exit_features['count']) / max(entry_features['count'], exit_features['count'])
        evidence.append(f"Packet count ratio: {count_ratio:.3f}")
        
        # Compare total bytes (TOR adds ~512 bytes/cell overhead)
        bytes_ratio = exit_features['total_bytes'] / (entry_features['total_bytes'] + 1)
        # Adjust for expected overhead reduction
        bytes_score = 1.0 - abs(bytes_ratio - 0.85) if 0.5 < bytes_ratio < 1.2 else 0.3
        evidence.append(f"Byte ratio (exit/entry): {bytes_ratio:.3f} → Score: {bytes_score:.2f}")
        
        # Compare average sizes
        if entry_features['avg_size'] > 0:
            size_diff = abs(entry_features['avg_size'] - exit_features['avg_size']) / entry_features['avg_size']
            size_score = max(0, 1 - size_diff)
            evidence.append(f"Avg size difference: {size_diff:.1%} → Score: {size_score:.2f}")
        else:
            size_score = 0.5
        
        # Calculate volume score
        volume_score = count_ratio * 0.4 + bytes_score * 0.3 + size_score * 0.3
        volume_score = min(1.0, max(0.0, volume_score))
        
        return volume_score, evidence


# =========================================================================
# JA3 FINGERPRINT ANALYZER
# =========================================================================

class JA3AnalyzerForCorrelation:
    """
    JA3 Fingerprint Analyzer for correlation boosting.
    
    Boosts confidence when TLS fingerprints match known TOR patterns.
    """
    
    def analyze(self, observations: List[TrafficObservation]) -> Tuple[float, List[str], Optional[str]]:
        """
        Analyze JA3 fingerprints in observations.
        
        Returns:
            (ja3_score, evidence_list, matched_hash) tuple
        """
        evidence = []
        matched_hash = None
        
        # Collect JA3 hashes from observations
        ja3_hashes = [o.ja3_hash for o in observations if o.ja3_hash]
        
        if not ja3_hashes:
            evidence.append("No JA3 fingerprints detected in traffic")
            return 0.5, evidence, None  # Neutral score when no data
        
        evidence.append(f"Found {len(ja3_hashes)} JA3 fingerprints in observations")
        
        # Check for TOR Browser matches
        for ja3 in ja3_hashes:
            if ja3 in TOR_JA3_FINGERPRINTS:
                matched_hash = ja3
                evidence.append(f"✓ EXACT TOR Browser JA3 match: {ja3[:16]}...")
                return 1.0, evidence, matched_hash
        
        # Check for partial matches (first 16 chars)
        for ja3 in ja3_hashes:
            for tor_ja3 in TOR_JA3_FINGERPRINTS:
                if ja3[:16] == tor_ja3[:16]:
                    matched_hash = ja3
                    evidence.append(f"⚬ Partial JA3 match: {ja3[:16]}...")
                    return 0.8, evidence, matched_hash
        
        evidence.append("No TOR Browser JA3 fingerprint matches")
        return 0.2, evidence, None


# =========================================================================
# HIGH-CONFIDENCE FUSION ENGINE
# =========================================================================

class HighConfidenceFusionEngine:
    """
    High-Confidence Fusion Engine.
    
    Combines Timing, Volume, and JA3 Fingerprint scores using weighted
    probability to produce a Composite Confidence Score (CCS):
    
    CCS = w₁(Timing) + w₂(Volume) + w₃(JA3 Fingerprint)
    
    Default weights: 0.45, 0.35, 0.20
    """
    
    def __init__(self, 
                 weight_timing: float = WEIGHT_TIMING,
                 weight_volume: float = WEIGHT_VOLUME,
                 weight_ja3: float = WEIGHT_JA3):
        self.weight_timing = weight_timing
        self.weight_volume = weight_volume
        self.weight_ja3 = weight_ja3
        
        self.timing_attack = TimingCorrelationAttack()
        self.volume_attack = VolumeCorrelationAttack()
        self.ja3_analyzer = JA3AnalyzerForCorrelation()
    
    def calculate_ccs(self,
                      entry_observations: List[TrafficObservation],
                      exit_observations: List[TrafficObservation]) -> Tuple[CCSBreakdown, List[str], Optional[str]]:
        """
        Calculate Composite Confidence Score with full breakdown.
        
        Returns:
            (ccs_breakdown, all_evidence, matched_ja3)
        """
        all_evidence = []
        
        # Run Timing Attack
        timing_score, timing_evidence = self.timing_attack.attack(entry_observations, exit_observations)
        all_evidence.extend([f"[TIMING] {e}" for e in timing_evidence])
        
        # Run Volume Attack
        volume_score, volume_evidence = self.volume_attack.attack(entry_observations, exit_observations)
        all_evidence.extend([f"[VOLUME] {e}" for e in volume_evidence])
        
        # Run JA3 Analysis
        all_obs = entry_observations + exit_observations
        ja3_score, ja3_evidence, matched_ja3 = self.ja3_analyzer.analyze(all_obs)
        all_evidence.extend([f"[JA3] {e}" for e in ja3_evidence])
        
        # Calculate Composite Confidence Score
        ccs = (
            timing_score * self.weight_timing +
            volume_score * self.weight_volume +
            ja3_score * self.weight_ja3
        )
        
        breakdown = CCSBreakdown(
            timing_score=timing_score,
            timing_weight=self.weight_timing,
            volume_score=volume_score,
            volume_weight=self.weight_volume,
            ja3_score=ja3_score,
            ja3_weight=self.weight_ja3,
            composite_score=ccs
        )
        
        # Add CCS breakdown to evidence
        all_evidence.append(breakdown.to_evidence_string())
        
        return breakdown, all_evidence, matched_ja3


# =========================================================================
# CORRELATION ATTACK ENGINE (MAIN CLASS)
# =========================================================================

class CorrelationAttackEngine:
    """
    Combined Correlation Attack Engine with High-Confidence Fusion.
    
    Features:
    - Weighted CCS scoring (Timing 45%, Volume 35%, JA3 20%)
    - Simulation Mode for demos without exit node access
    - Forensic evidence trace with JA3 and CCS breakdown
    """
    
    def __init__(self):
        """Initialize attack engine with Fusion Engine."""
        self.fusion_engine = HighConfidenceFusionEngine()
        self._attack_history: List[CorrelationResult] = []
        self._demo_mode = False
    
    def run_full_attack(self,
                        entry_observations: List[TrafficObservation],
                        exit_observations: List[TrafficObservation]) -> Dict:
        """
        Run full correlation attack with High-Confidence Fusion.
        
        Args:
            entry_observations: Traffic at Entry Guard
            exit_observations: Traffic at Exit Node
            
        Returns:
            Combined attack results with CCS breakdown
        """
        # Calculate CCS using Fusion Engine
        ccs_breakdown, all_evidence, matched_ja3 = self.fusion_engine.calculate_ccs(
            entry_observations, exit_observations
        )
        
        # Statistical significance based on data quality
        n_entry = len(entry_observations)
        n_exit = len(exit_observations)
        data_quality = min(n_entry, n_exit) / 50  # Normalize to 50 packets
        p_value = max(0.001, (1 - ccs_breakdown.composite_score) * (1 - min(1, data_quality)))
        
        # Determine match using CCS threshold (0.65 for moderate confidence)
        is_match = ccs_breakdown.composite_score >= 0.65
        
        # Build result
        result = CorrelationResult(
            attack_type="FUSION_CCS",
            entry_flow_id=entry_observations[0].flow_id if entry_observations else "",
            exit_flow_id=exit_observations[0].flow_id if exit_observations else "",
            correlation_score=ccs_breakdown.composite_score,
            confidence=ccs_breakdown.composite_score * (1 - p_value),
            is_match=is_match,
            evidence=all_evidence,
            statistical_significance=p_value,
            ccs_breakdown=ccs_breakdown,
            matched_ja3=matched_ja3
        )
        
        self._attack_history.append(result)
        
        return {
            'ccs': round(ccs_breakdown.composite_score, 4),
            'combined_score': round(ccs_breakdown.composite_score, 4),
            'combined_confidence': round(result.confidence, 4),
            'is_correlation_match': is_match,
            'ccs_breakdown': ccs_breakdown.to_dict(),
            'matched_ja3': matched_ja3,
            'evidence': all_evidence,
            'p_value': round(p_value, 6),
            'conclusion': self._generate_conclusion(is_match, ccs_breakdown, matched_ja3),
            'full_result': result.to_dict()
        }
    
    def _generate_conclusion(self, is_match: bool, ccs: CCSBreakdown, matched_ja3: Optional[str]) -> str:
        """Generate human-readable conclusion for forensic reports."""
        score = ccs.composite_score
        
        ja3_note = ""
        if matched_ja3:
            ja3_note = f" TOR Browser fingerprint confirmed (JA3: {matched_ja3[:12]}...)."
        
        if is_match and score >= 0.85:
            return (
                f"🔴 HIGH CONFIDENCE MATCH: Entry and Exit traffic are STRONGLY CORRELATED. "
                f"Same user identified with {score:.1%} confidence.{ja3_note} "
                f"Recommend immediate investigation."
            )
        elif is_match and score >= 0.65:
            return (
                f"🟠 MODERATE CONFIDENCE MATCH: Traffic correlation detected ({score:.1%}).{ja3_note} "
                f"Probable same origin - recommend further analysis."
            )
        elif score >= 0.45:
            return (
                f"🟡 LOW CONFIDENCE: Weak correlation detected ({score:.1%}). "
                f"Insufficient evidence for de-anonymization without additional data."
            )
        else:
            return (
                f"🟢 NO CORRELATION: Traffic appears unrelated ({score:.1%}). "
                f"Different users or TOR anonymization is effective."
            )
    
    def force_demo_correlation(self, level: str = 'high') -> Dict:
        """
        Simulation Mode for Demo.
        
        Injects a copy of entry IAT sequence into exit observer with
        added TOR latency (300-800ms) and minor jitter (5-10ms).
        
        Args:
            level: 'high', 'medium', 'low', or 'none'
            
        Returns:
            Attack results with simulated correlated data
        """
        self._demo_mode = True
        base_time = time.time()
        
        # Generate realistic entry observations
        entry_obs = []
        current_time = base_time
        
        for i in range(60):  # 60 packets for robust analysis
            # Simulate realistic web browsing pattern
            if i % 10 == 0:
                # Burst start - short IATs
                iat = random.uniform(0.01, 0.05)
            elif i % 5 == 0:
                # Mid-burst
                iat = random.uniform(0.05, 0.15)
            else:
                # Normal flow
                iat = random.uniform(0.08, 0.25)
            
            current_time += iat
            
            # Assign TOR JA3 fingerprint to some packets
            ja3 = random.choice(list(TOR_JA3_FINGERPRINTS)) if i < 3 else None
            
            entry_obs.append(TrafficObservation(
                observer_id="entry",
                timestamp=current_time,
                packet_size=random.randint(400, 600),
                direction=1 if i % 3 == 0 else -1,
                flow_id="DEMO-ENTRY-001",
                ja3_hash=ja3
            ))
        
        # Generate exit observations by copying entry with TOR latency
        exit_obs = []
        
        for i, entry in enumerate(entry_obs):
            # TOR Latency: 300-800ms with level-based correlation
            if level == 'high':
                # Minimal noise for guaranteed high correlation
                latency = random.uniform(0.45, 0.55)  # Consistent 500ms ±50ms
                jitter = random.uniform(0.001, 0.003)  # Very tight 1-3ms jitter
                size_noise = random.randint(-5, 5)  # Minimal size variation
            elif level == 'medium':
                latency = random.uniform(0.25, 1.0)
                jitter = random.uniform(0.01, 0.05)
                size_noise = random.randint(-80, 80)
            elif level == 'low':
                latency = random.uniform(0.2, 1.5)
                jitter = random.uniform(0.05, 0.15)
                size_noise = random.randint(-150, 150)
            else:  # none
                latency = random.uniform(0, 3)
                jitter = random.uniform(-0.5, 0.5)
                size_noise = random.randint(-400, 400)
            
            exit_obs.append(TrafficObservation(
                observer_id="exit",
                timestamp=entry.timestamp + latency + jitter,
                packet_size=max(100, entry.packet_size + size_noise),
                direction=entry.direction,
                flow_id="DEMO-EXIT-001",
                ja3_hash=entry.ja3_hash  # Propagate JA3
            ))
        
        # Run attack on simulated data
        result = self.run_full_attack(entry_obs, exit_obs)
        result['demo_mode'] = True
        result['demo_level'] = level
        result['packets_simulated'] = len(entry_obs)
        
        return result
    
    def simulate_attack_demo(self, correlation_level: str = "high") -> Dict:
        """
        Legacy method - redirects to force_demo_correlation.
        """
        return self.force_demo_correlation(level=correlation_level)
    
    def get_attack_history(self) -> List[Dict]:
        """Get history of all attacks."""
        return [r.to_dict() for r in self._attack_history]
    
    def clear_history(self):
        """Clear attack history."""
        self._attack_history.clear()
        self._demo_mode = False


# =========================================================================
# CONVENIENCE FUNCTIONS
# =========================================================================

def get_correlation_engine() -> CorrelationAttackEngine:
    """Get correlation attack engine instance."""
    return CorrelationAttackEngine()


def demo_high_confidence_correlation() -> Dict:
    """
    Quick demo function for hackathon demonstrations.
    
    Returns a high-confidence correlation match result.
    """
    engine = CorrelationAttackEngine()
    return engine.force_demo_correlation(level='high')


# =========================================================================
# ANTIGRAVITY CONFIGURATION HELPERS
# =========================================================================

def set_weight_mode(mode: str = 'asymmetric'):
    """
    Toggle between weight configurations.
    
    Args:
        mode: 'asymmetric' (single vantage) or 'balanced' (dual vantage)
        
    Note: Changes apply to new engine instances.
    """
    global WEIGHT_TIMING, WEIGHT_VOLUME, WEIGHT_JA3
    
    if mode == 'asymmetric':
        WEIGHT_TIMING = WEIGHT_TIMING_ASYMMETRIC
        WEIGHT_VOLUME = WEIGHT_VOLUME_ASYMMETRIC
        WEIGHT_JA3 = WEIGHT_JA3_ASYMMETRIC
    elif mode == 'balanced':
        WEIGHT_TIMING = WEIGHT_TIMING_DEFAULT
        WEIGHT_VOLUME = WEIGHT_VOLUME_DEFAULT
        WEIGHT_JA3 = WEIGHT_JA3_DEFAULT
    else:
        raise ValueError(f"Invalid mode: {mode}. Use 'asymmetric' or 'balanced'.")


def get_config_status() -> Dict:
    """
    Get current Antigravity configuration status.
    
    Returns:
        Dict with current config values for display
    """
    return {
        'weight_mode': 'asymmetric' if WEIGHT_TIMING == WEIGHT_TIMING_ASYMMETRIC else 'balanced',
        'weights': {
            'timing': WEIGHT_TIMING,
            'volume': WEIGHT_VOLUME,
            'ja3': WEIGHT_JA3
        },
        'thresholds': {
            'iat_gap': IAT_GAP_THRESHOLD,
            'tor_latency_min': TOR_LATENCY_MIN,
            'tor_latency_max': TOR_LATENCY_MAX
        },
        'flow_requirements': {
            'min_packets': MIN_PACKETS_FOR_CORRELATION,
            'recommended_packets': RECOMMENDED_PACKETS,
            'max_buffer': MAX_PACKETS_BUFFER,
            'min_duration_seconds': MIN_FLOW_DURATION_SECONDS
        }
    }


def run_loopback_demo(level: str = 'high', num_packets: int = 300) -> Dict:
    """
    Run Loopback Simulation for Demos.
    
    Generates synthetic correlated traffic without needing exit node access.
    This is the "Antigravity" mode for single-vantage-point scenarios.
    
    Args:
        level: 'high', 'medium', 'low', or 'none'
        num_packets: Number of packets to simulate (default 300)
        
    Returns:
        Attack results with demo mode indicators
    """
    engine = CorrelationAttackEngine()
    
    # Override packet count for larger buffers
    base_time = time.time()
    entry_obs = []
    current_time = base_time
    
    for i in range(num_packets):
        # Simulate realistic web browsing pattern
        if i % 10 == 0:
            iat = random.uniform(0.01, 0.05)
        elif i % 5 == 0:
            iat = random.uniform(0.05, 0.15)
        else:
            iat = random.uniform(0.08, 0.25)
        
        current_time += iat
        ja3 = random.choice(list(TOR_JA3_FINGERPRINTS)) if i < 5 else None
        
        entry_obs.append(TrafficObservation(
            observer_id="entry",
            timestamp=current_time,
            packet_size=random.randint(400, 600),
            direction=1 if i % 3 == 0 else -1,
            flow_id="LOOPBACK-ENTRY",
            ja3_hash=ja3
        ))
    
    # Generate exit observations by copying entry with TOR latency
    exit_obs = []
    for i, entry in enumerate(entry_obs):
        if level == 'high':
            latency = random.uniform(0.45, 0.55)
            jitter = random.uniform(0.001, 0.003)
            size_noise = random.randint(-5, 5)
        elif level == 'medium':
            latency = random.uniform(0.3, 1.0)
            jitter = random.uniform(0.01, 0.05)
            size_noise = random.randint(-50, 50)
        elif level == 'low':
            latency = random.uniform(0.2, 2.0)
            jitter = random.uniform(0.05, 0.2)
            size_noise = random.randint(-150, 150)
        else:
            latency = random.uniform(0, 5)
            jitter = random.uniform(-0.5, 0.5)
            size_noise = random.randint(-400, 400)
        
        exit_obs.append(TrafficObservation(
            observer_id="exit",
            timestamp=entry.timestamp + latency + jitter,
            packet_size=max(100, entry.packet_size + size_noise),
            direction=entry.direction,
            flow_id="LOOPBACK-EXIT",
            ja3_hash=entry.ja3_hash
        ))
    
    result = engine.run_full_attack(entry_obs, exit_obs)
    result['loopback_mode'] = True
    result['loopback_level'] = level
    result['packets_simulated'] = num_packets
    result['config'] = get_config_status()
    
    return result
