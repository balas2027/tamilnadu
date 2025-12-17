"""
Multi-Feature Burst Correlation Engine.

Provides circuit segmentation and fingerprint generation for
Entry Node ↔ Exit Node traffic correlation.

Key techniques:
- IAT-based circuit segmentation
- Feature vector generation for each circuit
- Watermark generation for external matching
"""

import hashlib
import math
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


@dataclass
class CircuitSegment:
    """A segmented logical flow/circuit within a TCP stream."""
    segment_id: str
    start_time: float
    end_time: float
    packets: List[Dict]  # {size, timestamp, direction}
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time
    
    @property
    def packet_count(self) -> int:
        return len(self.packets)
    
    @property
    def total_bytes(self) -> int:
        return sum(abs(p['size']) for p in self.packets)


@dataclass
class CorrelationFingerprint:
    """
    Unique fingerprint for a traffic burst/circuit.
    
    Can be matched against observations from Exit Nodes
    for Entry↔Exit correlation.
    """
    fingerprint_id: str
    segment_id: str
    
    # Temporal features
    duration: float
    packet_count: int
    
    # Size features
    total_bytes: int
    avg_packet_size: float
    packet_size_std: float
    
    # Timing features
    iat_mean: float
    iat_std: float
    iat_sequence_hash: str  # Hash of IAT pattern
    
    # Directional features
    direction_sequence_hash: str  # Hash of +1/-1 pattern
    upload_ratio: float
    
    # Watermark (for external matching)
    watermark: str
    
    def to_dict(self) -> Dict:
        return {
            'fingerprint_id': self.fingerprint_id,
            'segment_id': self.segment_id,
            'duration': round(self.duration, 3),
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'avg_packet_size': round(self.avg_packet_size, 1),
            'iat_mean': round(self.iat_mean, 4),
            'iat_std': round(self.iat_std, 4),
            'upload_ratio': round(self.upload_ratio, 3),
            'watermark': self.watermark
        }
    
    def matches(self, other: 'CorrelationFingerprint', tolerance: float = 0.15) -> Tuple[bool, float]:
        """
        Check if this fingerprint matches another.
        
        Args:
            other: Another fingerprint
            tolerance: Allowed deviation (0.15 = 15%)
            
        Returns:
            (is_match, confidence_score)
        """
        score = 0.0
        max_score = 7.0
        
        # Duration match
        if self.duration > 0 and other.duration > 0:
            diff = abs(self.duration - other.duration) / max(self.duration, other.duration)
            if diff <= tolerance:
                score += 1.0
        
        # Packet count match
        if self.packet_count > 0 and other.packet_count > 0:
            diff = abs(self.packet_count - other.packet_count) / max(self.packet_count, other.packet_count)
            if diff <= tolerance:
                score += 1.0
        
        # Total bytes match
        if self.total_bytes > 0 and other.total_bytes > 0:
            diff = abs(self.total_bytes - other.total_bytes) / max(self.total_bytes, other.total_bytes)
            if diff <= tolerance:
                score += 1.0
        
        # IAT mean match
        if self.iat_mean > 0 and other.iat_mean > 0:
            diff = abs(self.iat_mean - other.iat_mean) / max(self.iat_mean, other.iat_mean)
            if diff <= tolerance:
                score += 1.0
        
        # IAT pattern hash match (strong indicator)
        if self.iat_sequence_hash == other.iat_sequence_hash:
            score += 2.0
        
        # Direction pattern match
        if self.direction_sequence_hash == other.direction_sequence_hash:
            score += 1.0
        
        confidence = score / max_score
        is_match = confidence >= 0.6
        
        return is_match, confidence


class BurstCorrelator:
    """
    Multi-Feature Burst Correlation Engine.
    
    Segments TCP streams into logical circuits and generates
    unique fingerprints for Entry↔Exit correlation.
    """
    
    # Default IAT gap threshold for circuit segmentation (seconds)
    DEFAULT_GAP_THRESHOLD = 2.0
    
    def __init__(self, gap_threshold: float = 2.0):
        """
        Initialize burst correlator.
        
        Args:
            gap_threshold: IAT gap (seconds) to split circuits
        """
        self.gap_threshold = gap_threshold
        self._segments: List[CircuitSegment] = []
        self._fingerprints: List[CorrelationFingerprint] = []
    
    def segment_stream(self, packets: List[Dict]) -> List[CircuitSegment]:
        """
        Segment a TCP stream into logical circuits based on IAT gaps.
        
        Args:
            packets: List of packets with 'size', 'timestamp', 'direction'
            
        Returns:
            List of CircuitSegment objects
        """
        if not packets:
            return []
        
        # Sort by timestamp
        sorted_packets = sorted(packets, key=lambda p: p.get('timestamp', 0))
        
        segments = []
        current_segment = []
        segment_start = sorted_packets[0].get('timestamp', 0)
        
        for i, packet in enumerate(sorted_packets):
            if i == 0:
                current_segment.append(packet)
                continue
            
            prev_time = sorted_packets[i-1].get('timestamp', 0)
            curr_time = packet.get('timestamp', 0)
            gap = curr_time - prev_time
            
            # If gap exceeds threshold, start new segment
            if gap > self.gap_threshold:
                if current_segment:
                    segment = CircuitSegment(
                        segment_id=self._generate_segment_id(segment_start, len(segments)),
                        start_time=segment_start,
                        end_time=sorted_packets[i-1].get('timestamp', 0),
                        packets=current_segment.copy()
                    )
                    segments.append(segment)
                
                current_segment = [packet]
                segment_start = curr_time
            else:
                current_segment.append(packet)
        
        # Add final segment
        if current_segment:
            segment = CircuitSegment(
                segment_id=self._generate_segment_id(segment_start, len(segments)),
                start_time=segment_start,
                end_time=sorted_packets[-1].get('timestamp', 0),
                packets=current_segment
            )
            segments.append(segment)
        
        self._segments = segments
        return segments
    
    def generate_fingerprint(self, segment: CircuitSegment) -> CorrelationFingerprint:
        """
        Generate a correlation fingerprint for a circuit segment.
        
        Args:
            segment: CircuitSegment to fingerprint
            
        Returns:
            CorrelationFingerprint
        """
        packets = segment.packets
        
        if not packets:
            return self._empty_fingerprint(segment.segment_id)
        
        # Extract features
        sizes = [abs(p.get('size', 0)) for p in packets]
        timestamps = [p.get('timestamp', 0) for p in packets]
        directions = [1 if p.get('direction', 1) > 0 else -1 for p in packets]
        
        # Calculate IATs
        iats = []
        for i in range(1, len(timestamps)):
            iat = timestamps[i] - timestamps[i-1]
            if iat > 0:
                iats.append(iat)
        
        # Size statistics
        avg_size = statistics.mean(sizes) if sizes else 0
        size_std = statistics.stdev(sizes) if len(sizes) > 1 else 0
        total_bytes = sum(sizes)
        
        # IAT statistics
        iat_mean = statistics.mean(iats) if iats else 0
        iat_std = statistics.stdev(iats) if len(iats) > 1 else 0
        
        # Generate hashes
        iat_hash = self._hash_sequence([round(t, 2) for t in iats[:50]])  # First 50 IATs
        dir_hash = self._hash_sequence(directions[:100])  # First 100 directions
        
        # Upload ratio
        upload_bytes = sum(p.get('size', 0) for p in packets if p.get('direction', 1) > 0)
        upload_ratio = upload_bytes / total_bytes if total_bytes > 0 else 0.5
        
        # Generate watermark (unique identifier for matching)
        watermark = self._generate_watermark(
            segment.duration, len(packets), total_bytes, iat_mean, dir_hash
        )
        
        fingerprint = CorrelationFingerprint(
            fingerprint_id=f"fp_{segment.segment_id}",
            segment_id=segment.segment_id,
            duration=segment.duration,
            packet_count=len(packets),
            total_bytes=total_bytes,
            avg_packet_size=avg_size,
            packet_size_std=size_std,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_sequence_hash=iat_hash,
            direction_sequence_hash=dir_hash,
            upload_ratio=upload_ratio,
            watermark=watermark
        )
        
        return fingerprint
    
    def generate_all_fingerprints(self, packets: List[Dict]) -> List[CorrelationFingerprint]:
        """
        Segment stream and generate fingerprints for all circuits.
        
        Args:
            packets: List of packets
            
        Returns:
            List of CorrelationFingerprints
        """
        segments = self.segment_stream(packets)
        fingerprints = [self.generate_fingerprint(seg) for seg in segments]
        self._fingerprints = fingerprints
        return fingerprints
    
    def find_correlations(self, 
                          entry_fingerprints: List[CorrelationFingerprint],
                          exit_fingerprints: List[CorrelationFingerprint],
                          tolerance: float = 0.15) -> List[Dict]:
        """
        Find correlating fingerprints between Entry and Exit observations.
        
        Args:
            entry_fingerprints: Fingerprints from Entry Guard observation
            exit_fingerprints: Fingerprints from Exit Node observation
            tolerance: Matching tolerance
            
        Returns:
            List of correlation matches with confidence scores
        """
        correlations = []
        
        for entry_fp in entry_fingerprints:
            for exit_fp in exit_fingerprints:
                is_match, confidence = entry_fp.matches(exit_fp, tolerance)
                
                if is_match:
                    correlations.append({
                        'entry_fingerprint': entry_fp.fingerprint_id,
                        'exit_fingerprint': exit_fp.fingerprint_id,
                        'confidence': confidence,
                        'entry_watermark': entry_fp.watermark,
                        'exit_watermark': exit_fp.watermark
                    })
        
        # Sort by confidence
        correlations.sort(key=lambda x: -x['confidence'])
        
        return correlations
    
    def get_segments(self) -> List[CircuitSegment]:
        """Get the last segmented circuits."""
        return self._segments
    
    def get_fingerprints(self) -> List[CorrelationFingerprint]:
        """Get the last generated fingerprints."""
        return self._fingerprints
    
    def _generate_segment_id(self, start_time: float, index: int) -> str:
        """Generate unique segment ID."""
        return f"seg_{int(start_time)}_{index}"
    
    def _hash_sequence(self, sequence: List) -> str:
        """Generate hash of a sequence."""
        if not sequence:
            return "empty"
        
        seq_str = ",".join(str(x) for x in sequence)
        return hashlib.md5(seq_str.encode()).hexdigest()[:16]
    
    def _generate_watermark(self, duration: float, pkt_count: int, 
                           total_bytes: int, iat_mean: float, dir_hash: str) -> str:
        """
        Generate unique watermark for external matching.
        
        The watermark encodes key features that survive TOR's
        3-hop routing while remaining statistically unique.
        """
        # Quantize features to allow for slight timing variations
        dur_q = round(duration, 1)
        iat_q = round(iat_mean, 3)
        
        watermark_data = f"{dur_q}|{pkt_count}|{total_bytes}|{iat_q}|{dir_hash}"
        return hashlib.sha256(watermark_data.encode()).hexdigest()[:24]
    
    def _empty_fingerprint(self, segment_id: str) -> CorrelationFingerprint:
        """Create empty fingerprint for empty segment."""
        return CorrelationFingerprint(
            fingerprint_id=f"fp_{segment_id}",
            segment_id=segment_id,
            duration=0,
            packet_count=0,
            total_bytes=0,
            avg_packet_size=0,
            packet_size_std=0,
            iat_mean=0,
            iat_std=0,
            iat_sequence_hash="empty",
            direction_sequence_hash="empty",
            upload_ratio=0.5,
            watermark="empty"
        )


def create_packet_list(sizes: List[int], timestamps: List[float]) -> List[Dict]:
    """
    Helper function to create packet list from sizes and timestamps.
    
    Args:
        sizes: Packet sizes (positive=outgoing, negative=incoming)
        timestamps: Packet timestamps
        
    Returns:
        List of packet dictionaries
    """
    if len(sizes) != len(timestamps):
        raise ValueError("Sizes and timestamps must have same length")
    
    return [
        {
            'size': abs(s),
            'timestamp': t,
            'direction': 1 if s >= 0 else -1
        }
        for s, t in zip(sizes, timestamps)
    ]
