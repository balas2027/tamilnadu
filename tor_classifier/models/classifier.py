"""
TOR Classifier Module.

Binary classification model (TOR vs Non-TOR) using
a hybrid approach: Rule-based heuristics + ML backup.

The primary detection uses heuristics (ports, IPs, patterns).
ML is used only as supplementary scoring.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
import random

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# EXTENSIVE TOR RELAY IP PREFIXES
TOR_RELAY_PREFIXES = [
    # Major operators
    '185.220.100.', '185.220.101.', '185.220.102.', '185.220.103.', '185.220.104.',
    '199.249.230.', '199.249.231.',
    '162.247.72.', '162.247.73.', '162.247.74.',
    '89.234.157.', '87.118.122.', '87.118.116.',
    '213.164.204.', '46.165.230.', '23.129.64.',
    '193.218.118.', '178.17.170.', '178.17.171.',
    '104.244.72.', '104.244.73.', '104.244.74.', '104.244.75.', '104.244.76.',
    '45.66.33.', '171.25.193.', '209.141.58.',
    # OVH ranges
    '51.15.', '51.38.', '51.68.', '51.75.', '51.77.', '51.79.', '51.83.', '51.89.', '51.91.', '51.158.',
    # Hetzner
    '88.198.', '88.99.', '136.243.', '138.201.', '144.76.', '148.251.',
    # Other providers
    '5.199.', '5.2.', '5.9.', '176.10.', '176.126.',
    '37.187.', '37.120.', '62.210.', '62.102.',
    '78.46.', '78.47.', '81.7.', '81.169.', '85.25.',
    '91.121.', '91.219.', '91.232.', '92.60.', '92.222.',
    '94.23.', '94.130.', '95.128.', '95.142.', '95.211.',
    '109.70.', '128.31.', '158.69.', '163.172.',
    '167.86.', '167.114.', '176.58.', '178.62.', '178.63.',
    '185.56.', '185.100.', '185.107.', '185.129.', '185.165.', '185.195.',
    '188.138.', '188.166.', '192.42.', '192.87.',
    '193.11.', '193.234.', '194.26.', '194.32.', '195.154.',
    '198.50.', '198.96.', '198.98.', '204.8.', '204.13.',
    '212.83.', '212.129.', '213.61.', '213.95.', '217.79.', '217.182.',
]

# TOR-specific ports
TOR_PORTS = {9001, 9030, 9050, 9150, 9051}
TOR_SOCKS_PORTS = {9050, 9150, 9051}

# Localhost for SOCKS detection
LOCALHOST_PREFIXES = ['127.', '::1']


@dataclass
class ClassificationResult:
    """Result of TOR/Non-TOR classification."""
    is_tor: bool
    confidence: float
    label: str
    detection_method: str = "unknown"
    indicators: List[str] = field(default_factory=list)
    features_used: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'is_tor': self.is_tor,
            'confidence': round(self.confidence, 3),
            'label': self.label,
            'detection_method': self.detection_method,
            'indicators': self.indicators,
            'features_used': self.features_used
        }


class TORClassifier:
    """
    Hybrid TOR classifier using rule-based heuristics + ML.
    
    Detection priority:
    1. Localhost SOCKS (127.0.0.1:9050/9150) - DEFINITIVE
    2. TOR-specific ports (9001, 9030) - DEFINITIVE
    3. Known TOR relay IPs - STRONG
    4. TLS + likely TOR port (443) + TOR IP patterns - STRONG
    5. TOR cell size patterns (512-586 bytes) - MEDIUM
    6. ML prediction as backup - WEAK
    """
    
    FEATURE_NAMES = [
        'duration',
        'total_packets',
        'total_bytes',
        'packets_per_second',
        'bytes_per_second',
        'avg_packet_size',
        'iat_mean',
        'iat_std',
        'iat_min',
        'iat_max',
        'initial_packet_size',
        'tls_handshake_detected',
        'port_443_ratio',
        'port_9001_ratio',
        'size_entropy'
    ]
    
    def __init__(self):
        """Initialize TOR Classifier."""
        self.model = None
        self.is_trained = False
        self.training_metrics: Dict[str, float] = {}
        
    def _is_localhost(self, ip: str) -> bool:
        """Check if IP is localhost."""
        return any(ip.startswith(p) for p in LOCALHOST_PREFIXES)
    
    def _is_tor_relay_ip(self, ip: str) -> bool:
        """Check if IP matches known TOR relay prefixes."""
        return any(ip.startswith(prefix) for prefix in TOR_RELAY_PREFIXES)
    
    def _is_tor_port(self, port: int) -> bool:
        """Check if port is TOR-specific."""
        return port in TOR_PORTS
    
    def _is_socks_port(self, port: int) -> bool:
        """Check if port is TOR SOCKS."""
        return port in TOR_SOCKS_PORTS
    
    def _is_tor_cell_size(self, size: float) -> bool:
        """Check if packet size is close to TOR cell size."""
        tor_sizes = [512, 514, 536, 548, 558, 586, 509, 498, 566, 574, 582, 594, 602]
        for tor_size in tor_sizes:
            if abs(size - tor_size) <= 20:  # Allow 20 byte tolerance
                return True
        return False
    
    def _detect_by_rules(self, flow_info: Dict) -> Tuple[bool, float, str, List[str]]:
        """
        Rule-based TOR detection.
        
        Returns:
            (is_tor, confidence, method, indicators)
        """
        indicators = []
        confidence = 0.0
        method = "rule-based"
        
        dst_ip = flow_info.get('dst_ip', '')
        src_ip = flow_info.get('src_ip', '')
        dst_port = flow_info.get('dst_port', 0)
        src_port = flow_info.get('src_port', 0)
        avg_packet_size = flow_info.get('avg_packet_size', 0)
        tls_detected = flow_info.get('tls_handshake_detected', False)
        
        # Rule 1: Localhost SOCKS (DEFINITIVE - 95%)
        if self._is_localhost(dst_ip) and self._is_socks_port(dst_port):
            indicators.append(f"Localhost SOCKS proxy :{dst_port}")
            confidence = 0.95
            return True, confidence, "socks_proxy", indicators
        
        if self._is_localhost(src_ip) and self._is_socks_port(src_port):
            indicators.append(f"SOCKS response from :{src_port}")
            confidence = 0.90
            return True, confidence, "socks_proxy", indicators
        
        # Rule 2: TOR-specific ORPorts (DEFINITIVE - 90%)
        if dst_port in [9001, 9030]:
            indicators.append(f"TOR ORPort {dst_port}")
            confidence = 0.90
            return True, confidence, "orport", indicators
        
        # Rule 3: Known TOR relay IP (STRONG - 85%)
        if self._is_tor_relay_ip(dst_ip):
            indicators.append(f"TOR relay IP {dst_ip[:15]}...")
            confidence = 0.85
            
            # Boost if also TLS
            if tls_detected:
                confidence = min(0.95, confidence + 0.10)
                indicators.append("TLS encrypted")
            
            return True, confidence, "relay_ip", indicators
        
        # Rule 4: TLS + Port 443 + TOR cell sizes (MEDIUM - 70%)
        if tls_detected and dst_port == 443:
            if avg_packet_size and self._is_tor_cell_size(avg_packet_size):
                indicators.append(f"TOR cell size pattern (~{int(avg_packet_size)})")
                indicators.append("TLS on port 443")
                confidence = 0.70
                return True, confidence, "cell_pattern", indicators
        
        # Rule 5: TOR cell sizes alone (WEAK - 50%)
        if avg_packet_size and self._is_tor_cell_size(avg_packet_size):
            indicators.append(f"TOR-like packet size (~{int(avg_packet_size)})")
            confidence = 0.50
            # Don't return yet - let ML weigh in
        
        return False, confidence, method, indicators
    
    def _generate_synthetic_sample(self, is_tor: bool) -> np.ndarray:
        """Generate a synthetic training sample."""
        if is_tor:
            duration = random.uniform(5.0, 300.0)
            total_packets = random.randint(50, 500)
            avg_packet_size = random.gauss(540, 30)
            total_bytes = int(total_packets * avg_packet_size)
            packets_per_second = total_packets / duration
            bytes_per_second = total_bytes / duration
            iat_mean = random.gauss(0.05, 0.015)
            iat_std = random.gauss(0.01, 0.003)
            iat_min = random.uniform(0.001, 0.01)
            iat_max = random.uniform(0.1, 0.5)
            initial_packet_size = random.choice([512, 548, 586])
            tls_detected = 1.0
            port_443_ratio = random.uniform(0.7, 1.0)
            port_9001_ratio = random.uniform(0.0, 0.3)
            size_entropy = random.uniform(1.5, 3.0)
        else:
            duration = random.uniform(0.5, 120.0)
            total_packets = random.randint(10, 300)
            avg_packet_size = random.uniform(100, 1200)
            total_bytes = int(total_packets * avg_packet_size)
            packets_per_second = total_packets / duration
            bytes_per_second = total_bytes / duration
            iat_mean = random.uniform(0.001, 0.2)
            iat_std = random.uniform(0.01, 0.15)
            iat_min = random.uniform(0.0001, 0.01)
            iat_max = random.uniform(0.2, 2.0)
            initial_packet_size = random.randint(60, 1500)
            tls_detected = random.choice([0.0, 1.0])
            port_443_ratio = random.uniform(0.0, 0.8)
            port_9001_ratio = 0.0
            size_entropy = random.uniform(3.0, 7.0)
        
        return np.array([
            duration, total_packets, total_bytes,
            packets_per_second, bytes_per_second, avg_packet_size,
            iat_mean, iat_std, iat_min, iat_max,
            initial_packet_size, tls_detected,
            port_443_ratio, port_9001_ratio, size_entropy
        ])
    
    def generate_training_data(self, n_samples: int = 2000) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data."""
        features = []
        labels = []
        
        for _ in range(n_samples // 2):
            features.append(self._generate_synthetic_sample(is_tor=True))
            labels.append(1)
        
        for _ in range(n_samples // 2):
            features.append(self._generate_synthetic_sample(is_tor=False))
            labels.append(0)
        
        combined = list(zip(features, labels))
        random.shuffle(combined)
        features, labels = zip(*combined)
        
        return np.array(features), np.array(labels)
    
    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict[str, float]:
        """Train the classifier."""
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn required. Install: pip install scikit-learn")
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
        
        self.model = GradientBoostingClassifier(
            n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42
        )
        self.model.fit(X_train, y_train)
        
        y_pred = self.model.predict(X_test)
        
        self.training_metrics = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred, zero_division=0)),
            'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
            'train_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        self.is_trained = True
        return self.training_metrics
    
    def train_with_synthetic_data(self, n_samples: int = 2000) -> Dict[str, float]:
        """Train with synthetic data."""
        X, y = self.generate_training_data(n_samples)
        return self.train(X, y)
    
    def predict(self, 
                features: np.ndarray, 
                flow_id: Optional[str] = None,
                flow_info: Optional[Dict] = None) -> ClassificationResult:
        """
        Classify using hybrid approach: rules first, then ML.
        
        Args:
            features: 15-element feature vector
            flow_id: Optional flow identifier
            flow_info: Optional flow metadata for heuristics
            
        Returns:
            ClassificationResult
        """
        indicators = []
        detection_method = "ml"
        
        # First, try rule-based detection
        if flow_info:
            is_tor, confidence, method, rule_indicators = self._detect_by_rules(flow_info)
            indicators.extend(rule_indicators)
            
            if confidence >= 0.70:
                # High confidence rule match - use it
                return ClassificationResult(
                    is_tor=is_tor,
                    confidence=confidence,
                    label="TOR" if is_tor else "Non-TOR",
                    detection_method=method,
                    indicators=indicators,
                    features_used=[]
                )
            elif confidence >= 0.40:
                # Medium confidence - combine with ML
                detection_method = f"hybrid_{method}"
        
        # Fall back to ML prediction
        if not self.is_trained:
            self.train_with_synthetic_data()
        
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        ml_confidence = float(max(probabilities))
        
        # Combine confidence if we have rule-based indicators
        if flow_info:
            _, rule_confidence, _, _ = self._detect_by_rules(flow_info)
            
            if rule_confidence > 0:
                # Weighted combination: 70% rules, 30% ML
                final_confidence = 0.7 * rule_confidence + 0.3 * ml_confidence
                is_tor = final_confidence >= 0.45  # Lower threshold
                indicators.append(f"ML: {ml_confidence:.0%} {'TOR' if prediction else 'Non-TOR'}")
            else:
                final_confidence = ml_confidence
                is_tor = bool(prediction == 1)
        else:
            final_confidence = ml_confidence
            is_tor = bool(prediction == 1)
        
        return ClassificationResult(
            is_tor=is_tor,
            confidence=final_confidence,
            label="TOR" if is_tor else "Non-TOR",
            detection_method=detection_method,
            indicators=indicators,
            features_used=self.FEATURE_NAMES
        )
    
    def predict_from_flow(self, flow_features) -> ClassificationResult:
        """Classify using FlowFeatures object."""
        features = flow_features.to_feature_vector()
        flow_info = {
            'dst_ip': flow_features.dst_ip,
            'src_ip': getattr(flow_features, 'src_ip', ''),
            'dst_port': flow_features.dst_port,
            'src_port': flow_features.src_port,
            'avg_packet_size': flow_features.avg_packet_size,
            'tls_handshake_detected': flow_features.tls_handshake_detected
        }
        return self.predict(features, flow_features.flow_id, flow_info)
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from trained model."""
        if not self.is_trained or self.model is None:
            return {}
        
        importances = self.model.feature_importances_
        return {name: float(imp) for name, imp in zip(self.FEATURE_NAMES, importances)}

