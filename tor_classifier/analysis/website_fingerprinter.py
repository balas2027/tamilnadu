"""
Website Fingerprinting Module.

Identifies which website a TOR user might be visiting by matching
traffic patterns to known website templates.

WARNING: Website fingerprinting on TOR is an active research area.
This implementation is for educational/demonstration purposes.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
from collections import Counter


@dataclass
class WebsiteTemplate:
    """
    Traffic signature template for a known website.
    
    Each website has a unique "fingerprint" based on:
    - Packet count for page load
    - Total bytes transferred
    - Page load duration
    - Packet size distribution
    - Burst patterns
    """
    name: str
    category: str
    avg_packet_count: int
    avg_total_bytes: int
    avg_duration: float
    packet_size_distribution: List[int] = field(default_factory=list)
    burst_pattern: List[int] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'category': self.category,
            'avg_packet_count': self.avg_packet_count,
            'avg_total_bytes': self.avg_total_bytes,
            'avg_duration': self.avg_duration
        }


@dataclass
class FingerprintResult:
    """Result of website fingerprinting analysis."""
    matched_website: Optional[str]
    category: Optional[str]
    similarity_score: float
    confidence: float
    top_matches: List[Tuple[str, float]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'matched_website': self.matched_website,
            'category': self.category,
            'similarity_score': round(self.similarity_score, 3),
            'confidence': round(self.confidence, 3),
            'top_matches': [(name, round(score, 3)) for name, score in self.top_matches]
        }


class WebsiteFingerprinter:
    """
    Fingerprints TOR traffic to identify visited websites.
    
    Uses traffic analysis to match observed patterns against
    a database of known website signatures.
    """
    
    def __init__(self):
        """Initialize with default website templates."""
        self.templates: List[WebsiteTemplate] = self._load_default_templates()
        
    def _load_default_templates(self) -> List[WebsiteTemplate]:
        """Load default website templates."""
        return [
            # Search Engines
            WebsiteTemplate(
                name="Google Search",
                category="Search Engine",
                avg_packet_count=150,
                avg_total_bytes=120000,
                avg_duration=2.5,
                packet_size_distribution=[512] * 30 + [548] * 40 + [586] * 30,
                burst_pattern=[50, 30, 40, 30]
            ),
            WebsiteTemplate(
                name="DuckDuckGo",
                category="Search Engine",
                avg_packet_count=100,
                avg_total_bytes=85000,
                avg_duration=2.0,
                packet_size_distribution=[512] * 40 + [548] * 35 + [514] * 25,
                burst_pattern=[35, 25, 25, 15]
            ),
            
            # Social Media
            WebsiteTemplate(
                name="Twitter/X",
                category="Social Media",
                avg_packet_count=250,
                avg_total_bytes=180000,
                avg_duration=3.5,
                packet_size_distribution=[512] * 25 + [548] * 35 + [586] * 40,
                burst_pattern=[80, 60, 50, 40, 20]
            ),
            WebsiteTemplate(
                name="Reddit",
                category="Social Media",
                avg_packet_count=300,
                avg_total_bytes=220000,
                avg_duration=4.0,
                packet_size_distribution=[512] * 20 + [548] * 30 + [586] * 50,
                burst_pattern=[100, 70, 60, 50, 20]
            ),
            
            # News
            WebsiteTemplate(
                name="BBC News",
                category="News",
                avg_packet_count=200,
                avg_total_bytes=160000,
                avg_duration=3.0,
                packet_size_distribution=[512] * 30 + [548] * 40 + [558] * 30,
                burst_pattern=[60, 50, 45, 30, 15]
            ),
            WebsiteTemplate(
                name="CNN",
                category="News",
                avg_packet_count=280,
                avg_total_bytes=200000,
                avg_duration=3.5,
                packet_size_distribution=[512] * 25 + [548] * 35 + [586] * 40,
                burst_pattern=[90, 70, 60, 40, 20]
            ),
            
            # Video
            WebsiteTemplate(
                name="YouTube",
                category="Video",
                avg_packet_count=500,
                avg_total_bytes=500000,
                avg_duration=10.0,
                packet_size_distribution=[586] * 60 + [548] * 30 + [512] * 10,
                burst_pattern=[150, 100, 100, 80, 50, 20]
            ),
            
            # Email
            WebsiteTemplate(
                name="ProtonMail",
                category="Email",
                avg_packet_count=120,
                avg_total_bytes=90000,
                avg_duration=2.0,
                packet_size_distribution=[512] * 45 + [548] * 35 + [514] * 20,
                burst_pattern=[40, 35, 25, 20]
            ),
            
            # Anonymous Services
            WebsiteTemplate(
                name="Wikipedia",
                category="Reference",
                avg_packet_count=180,
                avg_total_bytes=140000,
                avg_duration=2.5,
                packet_size_distribution=[512] * 35 + [548] * 40 + [558] * 25,
                burst_pattern=[60, 45, 40, 25, 10]
            ),
            
            # E-commerce
            WebsiteTemplate(
                name="Amazon",
                category="E-commerce",
                avg_packet_count=350,
                avg_total_bytes=280000,
                avg_duration=4.5,
                packet_size_distribution=[512] * 20 + [548] * 30 + [586] * 50,
                burst_pattern=[100, 80, 70, 60, 30, 10]
            ),
        ]
    
    def add_template(self, template: WebsiteTemplate):
        """Add a custom website template."""
        self.templates.append(template)
    
    def _normalize(self, value: float, max_val: float) -> float:
        """Normalize a value to 0-1 range."""
        if max_val == 0:
            return 0.0
        return min(1.0, value / max_val)
    
    def _packet_similarity(self, 
                           observed: int, 
                           template: int, 
                           tolerance: float = 0.3) -> float:
        """Calculate packet count similarity."""
        if template == 0:
            return 0.0
        ratio = observed / template
        if 1 - tolerance <= ratio <= 1 + tolerance:
            # Within tolerance, high similarity
            return 1.0 - abs(1 - ratio) / tolerance
        return 0.0
    
    def _bytes_similarity(self, 
                          observed: int, 
                          template: int, 
                          tolerance: float = 0.3) -> float:
        """Calculate bytes similarity."""
        if template == 0:
            return 0.0
        ratio = observed / template
        if 1 - tolerance <= ratio <= 1 + tolerance:
            return 1.0 - abs(1 - ratio) / tolerance
        return 0.0
    
    def _duration_similarity(self, 
                             observed: float, 
                             template: float, 
                             tolerance: float = 0.4) -> float:
        """Calculate duration similarity."""
        if template == 0:
            return 0.0
        ratio = observed / template
        if 1 - tolerance <= ratio <= 1 + tolerance:
            return 1.0 - abs(1 - ratio) / tolerance
        return 0.0
    
    def _size_distribution_similarity(self, 
                                       observed: List[int], 
                                       template: List[int]) -> float:
        """
        Calculate packet size distribution similarity.
        
        Uses histogram comparison to match size distributions.
        """
        if not observed or not template:
            return 0.5  # Neutral score if no data
        
        # Create histograms
        bins = [500, 520, 540, 560, 580, 600]
        obs_hist, _ = np.histogram(observed, bins=bins, density=True)
        tpl_hist, _ = np.histogram(template, bins=bins, density=True)
        
        # Normalize
        obs_norm = obs_hist / (obs_hist.sum() + 1e-10)
        tpl_norm = tpl_hist / (tpl_hist.sum() + 1e-10)
        
        # Cosine similarity
        dot_product = np.dot(obs_norm, tpl_norm)
        magnitude = np.sqrt(np.dot(obs_norm, obs_norm)) * np.sqrt(np.dot(tpl_norm, tpl_norm))
        
        if magnitude == 0:
            return 0.5
        
        return float(dot_product / magnitude)
    
    def _burst_similarity(self, 
                          observed_timestamps: List[float], 
                          template_pattern: List[int]) -> float:
        """
        Calculate burst pattern similarity.
        
        Compares observed traffic bursts to template burst pattern.
        """
        if not observed_timestamps or not template_pattern:
            return 0.5
        
        # Detect bursts from timestamps
        sorted_ts = sorted(observed_timestamps)
        bursts = []
        current_burst = 1
        
        for i in range(1, len(sorted_ts)):
            if sorted_ts[i] - sorted_ts[i-1] < 0.5:  # 500ms threshold
                current_burst += 1
            else:
                bursts.append(current_burst)
                current_burst = 1
        bursts.append(current_burst)
        
        # Pad to same length
        max_len = max(len(bursts), len(template_pattern))
        bursts_padded = bursts + [0] * (max_len - len(bursts))
        template_padded = list(template_pattern) + [0] * (max_len - len(template_pattern))
        
        # Normalize and compare
        bursts_norm = np.array(bursts_padded) / (sum(bursts_padded) + 1e-10)
        template_norm = np.array(template_padded) / (sum(template_padded) + 1e-10)
        
        # Cosine similarity
        dot_product = np.dot(bursts_norm, template_norm)
        magnitude = np.sqrt(np.dot(bursts_norm, bursts_norm)) * np.sqrt(np.dot(template_norm, template_norm))
        
        if magnitude == 0:
            return 0.5
        
        return float(dot_product / magnitude)
    
    def calculate_similarity(self, flow: Dict, template: WebsiteTemplate) -> float:
        """
        Calculate overall similarity between flow and template.
        
        Uses weighted combination of multiple metrics.
        """
        weights = {
            'packets': 0.20,
            'bytes': 0.20,
            'duration': 0.15,
            'size_dist': 0.25,
            'burst': 0.20
        }
        
        scores = []
        
        # Packet count similarity
        packet_sim = self._packet_similarity(
            flow.get('total_packets', 0),
            template.avg_packet_count
        )
        scores.append(packet_sim * weights['packets'])
        
        # Bytes similarity
        bytes_sim = self._bytes_similarity(
            flow.get('total_bytes', 0),
            template.avg_total_bytes
        )
        scores.append(bytes_sim * weights['bytes'])
        
        # Duration similarity
        duration_sim = self._duration_similarity(
            flow.get('duration', 0),
            template.avg_duration
        )
        scores.append(duration_sim * weights['duration'])
        
        # Size distribution similarity
        sizes = flow.get('sizes', flow.get('packet_sizes', []))
        size_sim = self._size_distribution_similarity(
            sizes,
            template.packet_size_distribution
        )
        scores.append(size_sim * weights['size_dist'])
        
        # Burst pattern similarity
        timestamps = flow.get('timestamps', [])
        burst_sim = self._burst_similarity(
            timestamps,
            template.burst_pattern
        )
        scores.append(burst_sim * weights['burst'])
        
        return sum(scores)
    
    def fingerprint(self, flow: Dict) -> FingerprintResult:
        """
        Fingerprint a flow to identify potential website.
        
        Args:
            flow: Dictionary containing flow information:
                - total_packets: Packet count
                - total_bytes: Total bytes
                - duration: Flow duration
                - sizes/packet_sizes: List of packet sizes
                - timestamps: List of timestamps
                
        Returns:
            FingerprintResult with best matches
        """
        scores = []
        
        for template in self.templates:
            similarity = self.calculate_similarity(flow, template)
            scores.append((template.name, template.category, similarity))
        
        # Sort by similarity
        scores.sort(key=lambda x: x[2], reverse=True)
        
        # Get top matches
        top_matches = [(name, score) for name, _, score in scores[:5]]
        
        # Best match
        if scores and scores[0][2] > 0.3:  # Minimum threshold
            best_name, best_category, best_score = scores[0]
            
            # Calculate confidence based on margin over second best
            if len(scores) > 1:
                margin = best_score - scores[1][2]
                confidence = min(1.0, best_score + margin)
            else:
                confidence = best_score
            
            return FingerprintResult(
                matched_website=best_name,
                category=best_category,
                similarity_score=best_score,
                confidence=confidence,
                top_matches=top_matches
            )
        
        return FingerprintResult(
            matched_website=None,
            category=None,
            similarity_score=0.0,
            confidence=0.0,
            top_matches=top_matches
        )
    
    def get_templates(self) -> List[Dict]:
        """Get all templates as dictionaries."""
        return [t.to_dict() for t in self.templates]
