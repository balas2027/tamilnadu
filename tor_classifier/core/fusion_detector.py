"""
Fusion TOR Detector Module.

Combines all three detection phases into a unified high-confidence
TOR traffic detection system.

Phases:
1. Identity Check - Live TOR consensus matching (95-100% confidence)
2. Fingerprint Check - JA3/TLS fingerprinting (85-95% confidence)
3. Pattern Check - Traffic pattern ML analysis (60-80% confidence)

Final confidence is a weighted fusion of all phases.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum

from .consensus_fetcher import ConsensusFetcher, RelayInfo
from .ja3_fingerprinter import SimplifiedFingerprinter


class FusionClassification(Enum):
    """Classification result from fusion detector."""
    DEFINITIVE_TOR = "DEFINITIVE TOR"       # >= 0.95
    HIGH_CONFIDENCE_TOR = "HIGH-CONFIDENCE TOR"  # 0.80 - 0.95
    SUSPICIOUS = "SUSPICIOUS"                # 0.50 - 0.79
    NON_TOR = "NON-TOR"                     # < 0.50


@dataclass
class PhaseResult:
    """Result from a single detection phase."""
    phase_name: str
    confidence: float
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FusionResult:
    """Complete fusion detection result."""
    classification: FusionClassification
    confidence: float
    phase1_identity: PhaseResult
    phase2_fingerprint: PhaseResult
    phase3_pattern: PhaseResult
    relay_info: Optional[RelayInfo] = None
    indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'classification': self.classification.value,
            'confidence': round(self.confidence, 3),
            'phase1': {
                'name': self.phase1_identity.phase_name,
                'confidence': round(self.phase1_identity.confidence, 3),
                'reason': self.phase1_identity.reason
            },
            'phase2': {
                'name': self.phase2_fingerprint.phase_name,
                'confidence': round(self.phase2_fingerprint.confidence, 3),
                'reason': self.phase2_fingerprint.reason
            },
            'phase3': {
                'name': self.phase3_pattern.phase_name,
                'confidence': round(self.phase3_pattern.confidence, 3),
                'reason': self.phase3_pattern.reason
            },
            'relay': self.relay_info.to_dict() if self.relay_info else None,
            'indicators': self.indicators
        }


class FusionDetector:
    """
    High-confidence fusion TOR detector.
    
    Combines three detection phases with weighted scoring:
    - Phase 1 (Identity): 50% weight
    - Phase 2 (Fingerprint): 30% weight
    - Phase 3 (Pattern): 20% weight
    
    Classification thresholds:
    - DEFINITIVE TOR: >= 0.95 (Identity + Fingerprint match)
    - HIGH-CONFIDENCE TOR: 0.80 - 0.95 (Identity OR Fingerprint+Pattern)
    - SUSPICIOUS: 0.50 - 0.79 (Pattern only, no Identity/Fingerprint)
    - NON-TOR: < 0.50
    """
    
    # Phase weights (must sum to 1.0)
    WEIGHT_IDENTITY = 0.50
    WEIGHT_FINGERPRINT = 0.30
    WEIGHT_PATTERN = 0.20
    
    # Classification thresholds
    THRESHOLD_DEFINITIVE = 0.95
    THRESHOLD_HIGH_CONFIDENCE = 0.80
    THRESHOLD_SUSPICIOUS = 0.50
    
    def __init__(self, enable_consensus_fetch: bool = True):
        """
        Initialize fusion detector.
        
        Args:
            enable_consensus_fetch: Whether to fetch live TOR consensus
        """
        self.enable_consensus = enable_consensus_fetch
        self._consensus: Optional[ConsensusFetcher] = None
        self._fingerprinter = SimplifiedFingerprinter()
        
        if enable_consensus_fetch:
            self._consensus = ConsensusFetcher()
    
    def _phase1_identity(self, dst_ip: str, dst_port: int) -> PhaseResult:
        """
        Phase 1: Identity check against TOR consensus.
        
        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            
        Returns:
            PhaseResult with identity confidence
        """
        if not self._consensus:
            # Fall back to static port-based detection
            if dst_port == 9001:
                return PhaseResult(
                    phase_name="Identity (Static)",
                    confidence=0.70,
                    reason="TOR ORPort 9001",
                    details={'method': 'port_only'}
                )
            elif dst_port == 9030:
                return PhaseResult(
                    phase_name="Identity (Static)",
                    confidence=0.65,
                    reason="TOR DirPort 9030",
                    details={'method': 'port_only'}
                )
            return PhaseResult(
                phase_name="Identity (Static)",
                confidence=0.0,
                reason="Consensus not available",
                details={'method': 'none'}
            )
        
        # Get confidence from consensus
        confidence, reason = self._consensus.get_identity_confidence(dst_ip, dst_port)
        relay_info = self._consensus.get_relay_info(dst_ip)
        
        return PhaseResult(
            phase_name="Identity (Consensus)",
            confidence=confidence,
            reason=reason,
            details={
                'method': 'consensus',
                'is_guard': relay_info.is_guard if relay_info else False,
                'is_exit': relay_info.is_exit if relay_info else False,
                'nickname': relay_info.nickname if relay_info else None
            }
        )
    
    def _phase2_fingerprint(self, 
                            tls_detected: bool,
                            dst_port: int,
                            packet_sizes: List[int] = None,
                            ja3_hash: Optional[str] = None) -> PhaseResult:
        """
        Phase 2: Cryptographic fingerprint check.
        
        Args:
            tls_detected: Whether TLS was detected
            dst_port: Destination port
            packet_sizes: List of packet sizes
            ja3_hash: JA3 hash if available
            
        Returns:
            PhaseResult with fingerprint confidence
        """
        confidence, reason = self._fingerprinter.get_fingerprint_score(
            tls_detected=tls_detected,
            port=dst_port,
            packet_sizes=packet_sizes
        )
        
        return PhaseResult(
            phase_name="Fingerprint (TLS)",
            confidence=confidence,
            reason=reason,
            details={
                'tls_detected': tls_detected,
                'ja3_hash': ja3_hash,
                'has_tor_sizes': self._has_tor_handshake_sizes(packet_sizes)
            }
        )
    
    def _has_tor_handshake_sizes(self, sizes: List[int]) -> bool:
        """Check if packet sizes match TOR handshake pattern."""
        if not sizes or len(sizes) < 2:
            return False
        # TOR Client Hello is typically 500-650 bytes
        return any(450 <= s <= 650 for s in sizes[:5])
    
    def _phase3_pattern(self,
                        packet_sizes: List[int],
                        iat_mean: float,
                        iat_std: float,
                        duration: float,
                        ml_confidence: float = 0.0) -> PhaseResult:
        """
        Phase 3: Traffic pattern analysis.
        
        Args:
            packet_sizes: List of packet sizes
            iat_mean: Mean inter-arrival time
            iat_std: Standard deviation of IAT
            duration: Flow duration
            ml_confidence: ML model confidence if available
            
        Returns:
            PhaseResult with pattern confidence
        """
        confidence = 0.0
        reasons = []
        
        # Packet size consistency check
        if packet_sizes and len(packet_sizes) >= 5:
            tor_range_count = sum(1 for s in packet_sizes if 450 <= s <= 650)
            size_ratio = tor_range_count / len(packet_sizes)
            
            if size_ratio >= 0.6:
                confidence += 0.35
                reasons.append(f"Size pattern: {size_ratio*100:.0f}% in TOR range")
            elif size_ratio >= 0.4:
                confidence += 0.20
                reasons.append(f"Partial size pattern: {size_ratio*100:.0f}% in TOR range")
        
        # IAT variance check (CV = std/mean)
        if iat_mean > 0:
            cv = iat_std / iat_mean if iat_std >= 0 else 0
            if cv < 0.5:
                confidence += 0.25
                reasons.append(f"Low IAT variance (CV={cv:.2f})")
            elif cv < 0.8:
                confidence += 0.10
                reasons.append(f"Moderate IAT variance (CV={cv:.2f})")
        
        # Long-lived connection check (TOR circuits typically last 10+ minutes)
        if duration >= 600:
            confidence += 0.15
            reasons.append(f"Long-lived connection ({duration/60:.1f}min)")
        elif duration >= 60:
            confidence += 0.05
            reasons.append(f"Sustained connection ({duration:.0f}s)")
        
        # Add ML confidence if available
        if ml_confidence > 0:
            confidence += ml_confidence * 0.25
            reasons.append(f"ML model: {ml_confidence*100:.0f}%")
        
        confidence = min(confidence, 1.0)
        
        return PhaseResult(
            phase_name="Pattern (Statistical)",
            confidence=confidence,
            reason=" + ".join(reasons) if reasons else "No pattern indicators",
            details={
                'size_ratio': len([s for s in (packet_sizes or []) if 450 <= s <= 650]) / max(len(packet_sizes or [1]), 1),
                'iat_cv': iat_std / iat_mean if iat_mean > 0 else 0,
                'duration': duration,
                'ml_confidence': ml_confidence
            }
        )
    
    def detect(self, flow_info: Dict) -> FusionResult:
        """
        Perform fusion detection on a flow.
        
        Args:
            flow_info: Dictionary containing:
                - dst_ip: Destination IP
                - dst_port: Destination port
                - tls_handshake_detected: TLS detected
                - packet_sizes: List of packet sizes
                - iat_mean: Mean IAT
                - iat_std: IAT std dev
                - duration: Flow duration
                - ml_confidence: Optional ML confidence
                
        Returns:
            FusionResult with complete detection analysis
        """
        dst_ip = flow_info.get('dst_ip', '')
        dst_port = flow_info.get('dst_port', 0)
        tls_detected = flow_info.get('tls_handshake_detected', False)
        packet_sizes = flow_info.get('packet_sizes', [])
        iat_mean = flow_info.get('iat_mean', 0)
        iat_std = flow_info.get('iat_std', 0)
        duration = flow_info.get('duration', 0)
        ml_confidence = flow_info.get('ml_confidence', 0)
        
        # Run all phases
        phase1 = self._phase1_identity(dst_ip, dst_port)
        phase2 = self._phase2_fingerprint(tls_detected, dst_port, packet_sizes)
        phase3 = self._phase3_pattern(packet_sizes, iat_mean, iat_std, duration, ml_confidence)
        
        # Calculate weighted fusion score
        fusion_score = (
            self.WEIGHT_IDENTITY * phase1.confidence +
            self.WEIGHT_FINGERPRINT * phase2.confidence +
            self.WEIGHT_PATTERN * phase3.confidence
        )
        
        # Apply special rules for definitive classification
        # Identity + Fingerprint both high = DEFINITIVE
        if phase1.confidence >= 0.90 and phase2.confidence >= 0.70:
            fusion_score = max(fusion_score, 0.95)
        
        # Identity match alone with high confidence = at least HIGH_CONFIDENCE
        if phase1.confidence >= 0.95:
            fusion_score = max(fusion_score, 0.90)
        
        # Determine classification
        if fusion_score >= self.THRESHOLD_DEFINITIVE:
            classification = FusionClassification.DEFINITIVE_TOR
        elif fusion_score >= self.THRESHOLD_HIGH_CONFIDENCE:
            classification = FusionClassification.HIGH_CONFIDENCE_TOR
        elif fusion_score >= self.THRESHOLD_SUSPICIOUS:
            classification = FusionClassification.SUSPICIOUS
        else:
            classification = FusionClassification.NON_TOR
        
        # Collect indicators
        indicators = []
        if phase1.confidence > 0:
            indicators.append(f"Phase1: {phase1.reason}")
        if phase2.confidence > 0:
            indicators.append(f"Phase2: {phase2.reason}")
        if phase3.confidence > 0:
            indicators.append(f"Phase3: {phase3.reason}")
        
        # Get relay info if available
        relay_info = None
        if self._consensus and phase1.confidence > 0:
            relay_info = self._consensus.get_relay_info(dst_ip)
        
        return FusionResult(
            classification=classification,
            confidence=fusion_score,
            phase1_identity=phase1,
            phase2_fingerprint=phase2,
            phase3_pattern=phase3,
            relay_info=relay_info,
            indicators=indicators
        )
    
    def fetch_consensus(self, force: bool = False) -> bool:
        """
        Fetch/refresh TOR consensus.
        
        Args:
            force: Force refresh even if cache is valid
            
        Returns:
            True if successful
        """
        if self._consensus:
            return self._consensus.fetch_consensus(force)
        return False
    
    def get_consensus_stats(self) -> Dict:
        """Get consensus statistics."""
        if self._consensus:
            return self._consensus.get_stats()
        return {'error': 'Consensus not available'}
