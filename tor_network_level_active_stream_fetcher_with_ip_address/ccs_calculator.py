"""
CCS (Composite Confidence Score) Calculator Module.

Implements multi-feature correlation for TOR traffic detection.
Combines Identity, Fingerprint, and Pattern scores with weighted scoring.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import statistics

from .relay_database import RelayDatabase, get_relay_database
from .flow_tracker import NetworkFlow


@dataclass
class CCSResult:
    """
    Composite Confidence Score result.
    
    Contains:
    - Overall CCS score (0.0 - 1.0)
    - Component scores (identity, fingerprint, pattern)
    - Evidence list for forensic reporting
    """
    ccs_score: float
    identity_score: float
    fingerprint_score: float
    pattern_score: float
    is_tor: bool
    confidence_level: str  # High, Medium, Low
    evidence: List[str]
    relay_name: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'ccs_score': round(self.ccs_score, 4),
            'identity_score': round(self.identity_score, 4),
            'fingerprint_score': round(self.fingerprint_score, 4),
            'pattern_score': round(self.pattern_score, 4),
            'is_tor': self.is_tor,
            'confidence_level': self.confidence_level,
            'evidence': self.evidence,
            'relay_name': self.relay_name
        }


# TOR cell sizes for fingerprint analysis (strict 512 byte cells)
TOR_CELL_SIZE_MIN = 510
TOR_CELL_SIZE_MAX = 520

# Standard MTU range for normal traffic
MTU_SIZE_MIN = 1400
MTU_SIZE_MAX = 1500

# TOR-specific ports (NOT including 443 - that's normal HTTPS!)
TOR_ONLY_PORTS = {9001, 9030, 9050, 9150, 9151}


class CCSCalculator:
    """
    Composite Confidence Score Calculator.
    
    Implements the CCS formula with ZERO-TRUST Identity Filtering:
    CCS = (Identity × 0.45) + (Fingerprint × 0.35) + (Pattern × 0.20)
    
    CRITICAL: Identity Score is ONLY non-zero if destination IP is a VERIFIED TOR Relay.
    Port-based detection is NOT sufficient to trigger identity.
    """
    
    # CCS Component Weights
    WEIGHT_IDENTITY = 0.45
    WEIGHT_FINGERPRINT = 0.35
    WEIGHT_PATTERN = 0.20
    
    # Classification thresholds (raised for deterministic detection)
    TOR_THRESHOLD_HIGH = 0.75
    TOR_THRESHOLD_MEDIUM = 0.60
    TOR_THRESHOLD_LOW = 0.50  # Raised from 0.30 to reduce false positives
    
    def __init__(self, relay_database: Optional[RelayDatabase] = None):
        """
        Initialize CCS Calculator.
        
        Args:
            relay_database: RelayDatabase instance (default: singleton)
        """
        self.relay_db = relay_database or get_relay_database()
    
    def _calculate_identity_score(self, dst_ip: str, dst_port: int) -> Tuple[float, str]:
        """
        Calculate Identity Score (w=0.45) with ZERO-TRUST IP verification.
        
        CRITICAL: Destination IP MUST be in RelayDatabase to get ANY identity score.
        Port 443 alone does NOT trigger identity - only verified relay IPs count.
        
        Returns:
            (score, evidence_text)
        """
        # ZERO-TRUST: Check if destination is a VERIFIED TOR relay IP
        identity_score, reason = self.relay_db.get_identity_score(dst_ip, dst_port)
        
        if identity_score > 0:
            # Only return score if IP is verified in relay database
            return identity_score, f"Identity: {reason}"
        
        # Check if IP is a known relay (fallback)
        if self.relay_db.is_known_relay(dst_ip):
            # Known relay IP, but not in detailed database - give partial score
            if dst_port in TOR_ONLY_PORTS:
                return 0.7, f"Identity: Known TOR relay {dst_ip} on OR port {dst_port}"
            return 0.5, f"Identity: Known TOR relay {dst_ip}"
        
        # NOT a known TOR relay - NO identity score regardless of port
        # This is the key fix: port 443 on non-relay IPs returns 0
        return 0.0, ""
    
    def _calculate_fingerprint_score(self, packet_sizes: List[int]) -> Tuple[float, str]:
        """
        Calculate Fingerprint Score (w=0.35) using DISCRETE HISTOGRAM BINNING.
        
        TOR uses fixed 512-byte cells. Normal HTTPS uses variable MTU-sized packets.
        
        Bins:
        - TOR Cell Bin: 510-520 bytes (TOR's 512-byte cells with minimal overhead)
        - MTU Bin: 1400-1500 bytes (Standard MTU-sized packets)
        
        If TOR Cell Bin dominates -> TOR traffic
        If MTU Bin dominates -> Normal HTTPS/downloads
        
        Returns:
            (score, evidence_text)
        """
        if not packet_sizes or len(packet_sizes) < 5:
            return 0.0, ""
        
        total_packets = len(packet_sizes)
        
        # Count packets in each bin
        tor_cell_bin = sum(1 for s in packet_sizes if TOR_CELL_SIZE_MIN <= s <= TOR_CELL_SIZE_MAX)
        mtu_bin = sum(1 for s in packet_sizes if MTU_SIZE_MIN <= s <= MTU_SIZE_MAX)
        
        # Calculate ratios
        tor_cell_ratio = tor_cell_bin / total_packets
        mtu_ratio = mtu_bin / total_packets
        
        # DETERMINISTIC DECISION: TOR cells must significantly outnumber MTU packets
        if tor_cell_ratio >= 0.70:
            # Very strong TOR signal: 70%+ packets are exactly ~512 bytes
            return 0.95, f"Fingerprint: {tor_cell_bin}/{total_packets} packets in TOR cell bin (510-520 bytes)"
        
        if tor_cell_ratio >= 0.50 and mtu_ratio < 0.10:
            # Strong TOR signal: majority are TOR cells, very few MTU packets
            return 0.80, f"Fingerprint: {tor_cell_ratio:.0%} TOR cells, {mtu_ratio:.0%} MTU packets"
        
        if tor_cell_ratio >= 0.30 and tor_cell_ratio > mtu_ratio * 3:
            # Moderate TOR signal: significant cells and they dominate over MTU
            return 0.60, f"Fingerprint: TOR cell ratio ({tor_cell_ratio:.0%}) > MTU ratio ({mtu_ratio:.0%})"
        
        # If MTU packets dominate, this is likely normal HTTPS traffic
        if mtu_ratio > tor_cell_ratio:
            return 0.0, ""  # Normal traffic, no fingerprint match
        
        return 0.0, ""
    
    def _calculate_pattern_score(self, timestamps: List[float]) -> Tuple[float, str]:
        """
        Calculate Pattern Score (w=0.20) using BURST-SILENCE-BURST Analysis.
        
        TOR traffic exhibits "Burst-Silence-Burst" patterns due to circuit multiplexing.
        Simple low CV (consistent timing) is NOT sufficient - video streaming also has low CV.
        
        We detect:
        1. Burst periods: clusters of packets within short intervals
        2. Silence periods: gaps > 0.5 seconds between bursts
        3. TOR pattern: multiple bursts separated by silences
        
        Returns:
            (score, evidence_text)
        """
        if len(timestamps) < 10:  # Need enough packets to detect bursts
            return 0.0, ""
        
        # Calculate IAT sequence
        iats = []
        for i in range(1, len(timestamps)):
            iat = timestamps[i] - timestamps[i-1]
            if iat >= 0:
                iats.append(iat)
        
        if len(iats) < 5:
            return 0.0, ""
        
        # Define thresholds
        BURST_THRESHOLD = 0.05    # Packets within 50ms are in same burst
        SILENCE_THRESHOLD = 0.5   # Gaps > 500ms are silence periods
        
        # Count burst and silence transitions
        burst_count = 0
        silence_count = 0
        in_burst = False
        
        for iat in iats:
            if iat <= BURST_THRESHOLD:
                if not in_burst:
                    burst_count += 1
                    in_burst = True
            elif iat >= SILENCE_THRESHOLD:
                silence_count += 1
                in_burst = False
            else:
                in_burst = False
        
        # TOR multiplexing creates distinct Burst-Silence-Burst patterns
        # We need BOTH bursts AND silences, not just consistent timing
        
        if burst_count >= 3 and silence_count >= 2:
            # Clear Burst-Silence-Burst pattern - strong TOR indicator
            return 0.85, f"Pattern: Burst-Silence-Burst detected ({burst_count} bursts, {silence_count} silences)"
        
        if burst_count >= 2 and silence_count >= 1:
            # Some burst pattern
            return 0.50, f"Pattern: Partial burst pattern ({burst_count} bursts, {silence_count} silences)"
        
        # NO pattern score for steady streams (video, downloads)
        # This is the key fix: simple low CV doesn't give points
        return 0.0, ""
    
    def calculate(self, flow: NetworkFlow) -> CCSResult:
        """
        Calculate Composite Confidence Score for a network flow.
        
        Args:
            flow: NetworkFlow object
            
        Returns:
            CCSResult with scores and evidence
        """
        evidence = []
        relay_name = None
        
        # 1. Identity Score (w=0.45)
        identity_score, identity_evidence = self._calculate_identity_score(
            flow.dst_ip, flow.dst_port
        )
        if identity_evidence:
            evidence.append(identity_evidence)
        
        # Get relay name if known
        relay_info = self.relay_db.get_relay_info(flow.dst_ip)
        if relay_info:
            relay_name = relay_info.nickname
        
        # 2. Fingerprint Score (w=0.35)
        fingerprint_score, fingerprint_evidence = self._calculate_fingerprint_score(
            flow.packet_sizes
        )
        if fingerprint_evidence:
            evidence.append(fingerprint_evidence)
        
        # 3. Pattern Score (w=0.20)
        pattern_score, pattern_evidence = self._calculate_pattern_score(
            flow.timestamps
        )
        if pattern_evidence:
            evidence.append(pattern_evidence)
        
        # Calculate CCS
        ccs_score = (
            identity_score * self.WEIGHT_IDENTITY +
            fingerprint_score * self.WEIGHT_FINGERPRINT +
            pattern_score * self.WEIGHT_PATTERN
        )
        
        # Determine classification
        is_tor = ccs_score >= self.TOR_THRESHOLD_LOW
        
        if ccs_score >= self.TOR_THRESHOLD_HIGH:
            confidence_level = "High"
        elif ccs_score >= self.TOR_THRESHOLD_MEDIUM:
            confidence_level = "Medium"
        elif ccs_score >= self.TOR_THRESHOLD_LOW:
            confidence_level = "Low"
        else:
            confidence_level = "None"
        
        if not evidence:
            evidence.append("No TOR indicators detected")
        
        return CCSResult(
            ccs_score=ccs_score,
            identity_score=identity_score,
            fingerprint_score=fingerprint_score,
            pattern_score=pattern_score,
            is_tor=is_tor,
            confidence_level=confidence_level,
            evidence=evidence,
            relay_name=relay_name
        )
    
    def calculate_from_data(self, 
                           dst_ip: str, 
                           dst_port: int,
                           packet_sizes: List[int],
                           timestamps: List[float]) -> CCSResult:
        """
        Calculate CCS from raw data (without NetworkFlow object).
        
        Args:
            dst_ip: Destination IP
            dst_port: Destination port
            packet_sizes: List of packet sizes
            timestamps: List of packet timestamps
            
        Returns:
            CCSResult
        """
        # Create temporary flow-like structure
        class TempFlow:
            pass
        
        flow = TempFlow()
        flow.dst_ip = dst_ip
        flow.dst_port = dst_port
        flow.packet_sizes = packet_sizes
        flow.timestamps = timestamps
        
        return self.calculate(flow)
    
    def generate_forensic_report(self, 
                                src_ip: str, 
                                ccs_result: CCSResult,
                                flow: NetworkFlow) -> str:
        """
        Generate a forensic report for detected TOR activity.
        
        Args:
            src_ip: Source (internal) IP
            ccs_result: CCS calculation result
            flow: Network flow
            
        Returns:
            Formatted forensic report string
        """
        confidence_pct = ccs_result.ccs_score * 100
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                    TOR TRAFFIC FORENSIC REPORT                       ║
╠══════════════════════════════════════════════════════════════════════╣
║ Source IP:        {src_ip:<48} ║
║ Destination IP:   {flow.dst_ip:<48} ║
║ Destination Port: {flow.dst_port:<48} ║
║ Relay Name:       {ccs_result.relay_name or 'Unknown':<48} ║
╠══════════════════════════════════════════════════════════════════════╣
║ CORRELATION CONFIDENCE: {confidence_pct:.1f}%  [{ccs_result.confidence_level}]                         ║
╠══════════════════════════════════════════════════════════════════════╣
║ CCS BREAKDOWN:                                                       ║
║   - Identity Score:    {ccs_result.identity_score:.3f}  (weight: 0.45)                      ║
║   - Fingerprint Score: {ccs_result.fingerprint_score:.3f}  (weight: 0.35)                      ║
║   - Pattern Score:     {ccs_result.pattern_score:.3f}  (weight: 0.20)                      ║
╠══════════════════════════════════════════════════════════════════════╣
║ TRAFFIC STATISTICS:                                                  ║
║   - Packets:   {flow.packet_count:<54} ║
║   - Bytes:     {flow.total_bytes:<54} ║
║   - Duration:  {flow.duration:.2f}s{' ':<49} ║
╠══════════════════════════════════════════════════════════════════════╣
║ EVIDENCE:                                                            ║"""
        
        for ev in ccs_result.evidence:
            report += f"\n║   • {ev:<63} ║"
        
        report += """
╚══════════════════════════════════════════════════════════════════════╝"""
        
        return report


# Singleton instance
_ccs_calculator: Optional[CCSCalculator] = None


def get_ccs_calculator() -> CCSCalculator:
    """Get singleton CCS calculator instance."""
    global _ccs_calculator
    if _ccs_calculator is None:
        _ccs_calculator = CCSCalculator()
    return _ccs_calculator
