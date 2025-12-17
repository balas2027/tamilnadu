"""
Activity Fingerprinter Module.

Advanced traffic fingerprinting to classify activity types beyond
simple TOR/Non-TOR detection. Identifies behavioral patterns like:
- Marketplace browsing
- Botnet C2 communication
- File sharing/P2P
- Video streaming
- Standard web browsing
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum
from collections import Counter
import statistics


class ActivityType(Enum):
    """Types of network activity patterns."""
    UNKNOWN = "Unknown"
    WEB_BROWSING = "Web Browsing"
    MARKETPLACE = "Marketplace/Dark Web"
    BOTNET_C2 = "Botnet C2"
    FILE_SHARING = "File Sharing/P2P"
    VIDEO_STREAMING = "Video Streaming"
    CHAT_MESSAGING = "Chat/Messaging"
    API_AUTOMATED = "API/Automated"
    SEARCH_ENGINE = "Search Engine"


@dataclass
class ActivitySignature:
    """Template signature for an activity type."""
    activity_type: ActivityType
    
    # Burst characteristics
    burst_reversal_range: Tuple[int, int]  # (min, max) reversal count
    
    # Size characteristics
    avg_packet_size_range: Tuple[int, int]  # bytes
    total_bytes_range: Tuple[int, int]  # bytes
    
    # Timing characteristics  
    duration_range: Tuple[float, float]  # seconds
    iat_cv_range: Tuple[float, float]  # coefficient of variation
    
    # Directional characteristics
    upload_ratio_range: Tuple[float, float]  # 0.0-1.0
    
    # Optional: Fixed packet sizes (for C2 detection)
    fixed_packet_sizes: List[int] = field(default_factory=list)


@dataclass
class ActivityResult:
    """Result of activity classification."""
    detected_activity: ActivityType
    confidence: float
    scores: Dict[str, float]  # Activity type -> score
    indicators: List[str]
    is_automated: bool
    is_suspicious: bool
    
    def to_dict(self) -> Dict:
        return {
            'activity': self.detected_activity.value,
            'confidence': round(self.confidence, 3),
            'scores': {k: round(v, 3) for k, v in self.scores.items()},
            'indicators': self.indicators,
            'is_automated': self.is_automated,
            'is_suspicious': self.is_suspicious
        }


class ActivityFingerprinter:
    """
    Classifies network traffic into activity categories.
    
    Uses traffic signatures based on:
    - Burst patterns and reversal counts
    - Packet size distributions
    - Inter-arrival time statistics
    - Directional (upload/download) ratios
    """
    
    # Predefined activity signatures
    SIGNATURES = [
        ActivitySignature(
            activity_type=ActivityType.MARKETPLACE,
            burst_reversal_range=(10, 100),
            avg_packet_size_range=(200, 800),
            total_bytes_range=(50000, 500000),
            duration_range=(60, 1800),  # 1-30 min browsing
            iat_cv_range=(0.5, 2.0),
            upload_ratio_range=(0.2, 0.4),  # Some form submissions
        ),
        ActivitySignature(
            activity_type=ActivityType.BOTNET_C2,
            burst_reversal_range=(1, 10),
            avg_packet_size_range=(64, 600),
            total_bytes_range=(1000, 50000),
            duration_range=(1, 60),  # Short heartbeats
            iat_cv_range=(0.0, 0.3),  # Very regular timing
            upload_ratio_range=(0.4, 0.6),  # Bidirectional
            fixed_packet_sizes=[64, 128, 256, 512],
        ),
        ActivitySignature(
            activity_type=ActivityType.FILE_SHARING,
            burst_reversal_range=(0, 5),
            avg_packet_size_range=(1000, 1500),
            total_bytes_range=(1000000, 1000000000),  # 1MB - 1GB
            duration_range=(30, 7200),  # 30s - 2hr
            iat_cv_range=(0.2, 1.0),
            upload_ratio_range=(0.0, 0.15),  # Mostly download
        ),
        ActivitySignature(
            activity_type=ActivityType.VIDEO_STREAMING,
            burst_reversal_range=(0, 10),
            avg_packet_size_range=(800, 1500),
            total_bytes_range=(5000000, 500000000),  # 5MB - 500MB
            duration_range=(60, 10800),  # 1 min - 3 hr
            iat_cv_range=(0.1, 0.5),  # Steady stream
            upload_ratio_range=(0.0, 0.05),  # Almost all download
        ),
        ActivitySignature(
            activity_type=ActivityType.CHAT_MESSAGING,
            burst_reversal_range=(20, 200),
            avg_packet_size_range=(50, 500),
            total_bytes_range=(5000, 100000),
            duration_range=(60, 3600),
            iat_cv_range=(1.0, 5.0),  # Very irregular (human typing)
            upload_ratio_range=(0.35, 0.65),  # Balanced
        ),
        ActivitySignature(
            activity_type=ActivityType.API_AUTOMATED,
            burst_reversal_range=(1, 50),
            avg_packet_size_range=(100, 2000),
            total_bytes_range=(1000, 1000000),
            duration_range=(0.1, 60),
            iat_cv_range=(0.0, 0.2),  # Very regular
            upload_ratio_range=(0.3, 0.7),
        ),
        ActivitySignature(
            activity_type=ActivityType.WEB_BROWSING,
            burst_reversal_range=(5, 50),
            avg_packet_size_range=(300, 1200),
            total_bytes_range=(50000, 5000000),
            duration_range=(5, 300),
            iat_cv_range=(0.5, 3.0),
            upload_ratio_range=(0.1, 0.3),
        ),
    ]
    
    def __init__(self):
        """Initialize activity fingerprinter."""
        self._templates = {sig.activity_type: sig for sig in self.SIGNATURES}
    
    def extract_directional_vector(self, packet_sizes: List[int]) -> List[int]:
        """
        Extract directional vector from packet sizes.
        
        Positive sizes = outgoing, negative = incoming (convention)
        Returns +1/-1 sequence.
        """
        if not packet_sizes:
            return []
        
        # Assuming positive = outgoing, we encode direction
        # In real implementation, this would come from flow direction
        return [1 if s > 0 else -1 for s in packet_sizes]
    
    def calculate_burst_reversals(self, directions: List[int]) -> int:
        """Count direction reversals (switches between up/down)."""
        if len(directions) < 2:
            return 0
        
        reversals = 0
        for i in range(1, len(directions)):
            if directions[i] != directions[i-1]:
                reversals += 1
        
        return reversals
    
    def calculate_iat_statistics(self, timestamps: List[float]) -> Dict[str, float]:
        """
        Calculate Inter-Arrival Time statistics.
        
        Returns mean, std, CV, skewness, kurtosis.
        """
        if len(timestamps) < 2:
            return {'mean': 0, 'std': 0, 'cv': 0, 'skewness': 0, 'kurtosis': 0}
        
        iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        iats = [t for t in iats if t > 0]  # Filter zero/negative
        
        if len(iats) < 2:
            return {'mean': 0, 'std': 0, 'cv': 0, 'skewness': 0, 'kurtosis': 0}
        
        mean = statistics.mean(iats)
        std = statistics.stdev(iats) if len(iats) > 1 else 0
        cv = std / mean if mean > 0 else 0
        
        # Skewness and kurtosis (Fisher's definition)
        skewness = 0
        kurtosis = 0
        
        if std > 0 and len(iats) >= 3:
            n = len(iats)
            skewness = sum(((x - mean) / std) ** 3 for x in iats) * n / ((n-1) * (n-2)) if n > 2 else 0
            if n > 3:
                kurtosis = (sum(((x - mean) / std) ** 4 for x in iats) * n * (n+1) / ((n-1) * (n-2) * (n-3))) - 3 * (n-1)**2 / ((n-2) * (n-3))
        
        return {
            'mean': mean,
            'std': std,
            'cv': cv,
            'skewness': skewness,
            'kurtosis': kurtosis
        }
    
    def detect_fixed_packet_sizes(self, sizes: List[int], tolerance: int = 10) -> List[int]:
        """Detect commonly occurring fixed packet sizes (C2 indicator)."""
        if not sizes:
            return []
        
        abs_sizes = [abs(s) for s in sizes]
        size_counts = Counter(abs_sizes)
        
        # Find sizes that occur frequently (>10% of packets)
        threshold = len(sizes) * 0.1
        fixed_sizes = [size for size, count in size_counts.items() if count >= threshold]
        
        return sorted(fixed_sizes)
    
    def classify_flow(self, flow_data: Dict) -> ActivityResult:
        """
        Classify a flow into an activity type.
        
        Args:
            flow_data: Dictionary containing:
                - packet_sizes: List of packet sizes
                - timestamps: List of timestamps
                - total_bytes: Total bytes transferred
                - duration: Flow duration in seconds
                
        Returns:
            ActivityResult with classification
        """
        packet_sizes = flow_data.get('packet_sizes', [])
        timestamps = flow_data.get('timestamps', [])
        total_bytes = flow_data.get('total_bytes', sum(abs(s) for s in packet_sizes))
        duration = flow_data.get('duration', 0)
        
        if not packet_sizes:
            return ActivityResult(
                detected_activity=ActivityType.UNKNOWN,
                confidence=0,
                scores={},
                indicators=["No packet data"],
                is_automated=False,
                is_suspicious=False
            )
        
        # Extract features
        directions = self.extract_directional_vector(packet_sizes)
        burst_reversals = self.calculate_burst_reversals(directions)
        iat_stats = self.calculate_iat_statistics(timestamps)
        fixed_sizes = self.detect_fixed_packet_sizes(packet_sizes)
        
        avg_packet_size = total_bytes / len(packet_sizes) if packet_sizes else 0
        upload_bytes = sum(s for s in packet_sizes if s > 0)
        upload_ratio = upload_bytes / total_bytes if total_bytes > 0 else 0.5
        
        # Score each activity type
        scores = {}
        indicators = []
        
        for activity_type, sig in self._templates.items():
            score = self._score_signature(
                sig,
                burst_reversals=burst_reversals,
                avg_packet_size=avg_packet_size,
                total_bytes=total_bytes,
                duration=duration,
                iat_cv=iat_stats['cv'],
                upload_ratio=upload_ratio,
                fixed_sizes=fixed_sizes
            )
            scores[activity_type.value] = score
        
        # Find best match
        best_activity = max(scores, key=scores.get)
        best_score = scores[best_activity]
        
        # Detect automation (low IAT variance)
        is_automated = iat_stats['cv'] < 0.3 and iat_stats['skewness'] < 0.5
        
        # Detect suspicious patterns
        is_suspicious = False
        
        # C2 indicators
        if fixed_sizes and len(fixed_sizes) <= 3 and is_automated:
            indicators.append(f"Fixed packet sizes detected: {fixed_sizes}")
            is_suspicious = True
        
        # Very regular timing
        if iat_stats['cv'] < 0.2:
            indicators.append(f"Highly regular timing (CV={iat_stats['cv']:.2f})")
            if best_activity != ActivityType.API_AUTOMATED.value:
                is_suspicious = True
        
        # Unusual burst pattern
        if burst_reversals > 100:
            indicators.append(f"High burst reversal count: {burst_reversals}")
        
        # Add feature indicators
        indicators.append(f"Avg packet size: {avg_packet_size:.0f}B")
        indicators.append(f"Upload ratio: {upload_ratio:.1%}")
        indicators.append(f"Duration: {duration:.1f}s")
        
        return ActivityResult(
            detected_activity=ActivityType(best_activity),
            confidence=best_score,
            scores=scores,
            indicators=indicators,
            is_automated=is_automated,
            is_suspicious=is_suspicious
        )
    
    def _score_signature(self, 
                         sig: ActivitySignature,
                         burst_reversals: int,
                         avg_packet_size: float,
                         total_bytes: int,
                         duration: float,
                         iat_cv: float,
                         upload_ratio: float,
                         fixed_sizes: List[int]) -> float:
        """Score how well traffic matches a signature."""
        score = 0.0
        max_score = 6.0
        
        # Burst reversal match
        if sig.burst_reversal_range[0] <= burst_reversals <= sig.burst_reversal_range[1]:
            score += 1.0
        elif burst_reversals < sig.burst_reversal_range[0]:
            score += 0.3
        
        # Packet size match
        if sig.avg_packet_size_range[0] <= avg_packet_size <= sig.avg_packet_size_range[1]:
            score += 1.0
        elif abs(avg_packet_size - sum(sig.avg_packet_size_range)/2) < 500:
            score += 0.3
        
        # Total bytes match
        if sig.total_bytes_range[0] <= total_bytes <= sig.total_bytes_range[1]:
            score += 1.0
        
        # Duration match
        if sig.duration_range[0] <= duration <= sig.duration_range[1]:
            score += 1.0
        
        # IAT CV match
        if sig.iat_cv_range[0] <= iat_cv <= sig.iat_cv_range[1]:
            score += 1.0
        
        # Upload ratio match
        if sig.upload_ratio_range[0] <= upload_ratio <= sig.upload_ratio_range[1]:
            score += 1.0
        
        # Bonus for fixed packet size match (C2 detection)
        if sig.fixed_packet_sizes and fixed_sizes:
            matching = len(set(fixed_sizes) & set(sig.fixed_packet_sizes))
            if matching > 0:
                score += 0.5
        
        return score / max_score
    
    def get_activity_templates(self) -> List[Dict]:
        """Get list of activity templates for reference."""
        return [
            {
                'type': sig.activity_type.value,
                'burst_reversal': sig.burst_reversal_range,
                'avg_packet_size': sig.avg_packet_size_range,
                'duration': sig.duration_range
            }
            for sig in self.SIGNATURES
        ]
