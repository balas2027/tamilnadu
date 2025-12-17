"""
Deep TOR Classifier Module.

4-class classification model for distinguishing:
- NON_TOR: Regular internet traffic
- TOR_ENTRY_GUARD: Connection to TOR guard node
- TOR_BRIDGE: Connection to TOR bridge (hidden relay)
- VPN: VPN tunnel traffic
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
import random

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score, 
        precision_score, 
        recall_score, 
        f1_score,
        confusion_matrix,
        classification_report
    )
    from sklearn.preprocessing import LabelEncoder
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@dataclass
class DeepClassificationResult:
    """Result of 4-class deep classification."""
    traffic_type: str
    confidence: float
    class_probabilities: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'traffic_type': self.traffic_type,
            'confidence': round(self.confidence, 3),
            'class_probabilities': {
                k: round(v, 3) for k, v in self.class_probabilities.items()
            }
        }


class DeepTORClassifier:
    """
    4-class traffic classifier.
    
    Classes:
    - NON_TOR (0): Regular internet traffic
    - TOR_ENTRY_GUARD (1): TOR guard node connection
    - TOR_BRIDGE (2): TOR bridge connection
    - VPN (3): VPN tunnel traffic
    
    Each class has distinctive traffic patterns:
    - TOR: Fixed cell sizes (~512 bytes), low IAT variance, TLS
    - Bridge: Similar to TOR but different ports/IPs
    - VPN: Larger packets, various ports (1194, 51820)
    - Non-TOR: High variance in all metrics
    """
    
    CLASSES = ['NON_TOR', 'TOR_ENTRY_GUARD', 'TOR_BRIDGE', 'VPN']
    
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
        """Initialize Deep TOR Classifier."""
        self.model = None
        self.label_encoder = None
        self.is_trained = False
        self.training_metrics: Dict[str, Any] = {}
        self.per_class_metrics: Dict[str, Dict[str, float]] = {}
        
    def _generate_sample(self, class_label: str) -> np.ndarray:
        """
        Generate a synthetic sample for a given class.
        
        Args:
            class_label: One of CLASSES
            
        Returns:
            15-element feature vector
        """
        if class_label == 'TOR_ENTRY_GUARD':
            # TOR Entry Guard characteristics
            duration = random.uniform(10.0, 300.0)
            total_packets = random.randint(100, 600)
            avg_packet_size = random.gauss(540, 25)  # Tight around cell size
            total_bytes = int(total_packets * avg_packet_size)
            
            packets_per_second = total_packets / duration
            bytes_per_second = total_bytes / duration
            
            iat_mean = random.gauss(0.05, 0.01)
            iat_std = random.gauss(0.008, 0.002)  # Very low variance
            iat_min = random.uniform(0.001, 0.008)
            iat_max = random.uniform(0.1, 0.4)
            
            initial_packet_size = random.choice([512, 548, 586])
            tls_detected = 1.0
            
            port_443_ratio = random.uniform(0.6, 1.0)
            port_9001_ratio = random.uniform(0.1, 0.4)
            
            size_entropy = random.uniform(1.5, 2.5)  # Low entropy
            
        elif class_label == 'TOR_BRIDGE':
            # TOR Bridge - similar to guard but different ports
            duration = random.uniform(10.0, 250.0)
            total_packets = random.randint(80, 500)
            avg_packet_size = random.gauss(545, 30)
            total_bytes = int(total_packets * avg_packet_size)
            
            packets_per_second = total_packets / duration
            bytes_per_second = total_bytes / duration
            
            iat_mean = random.gauss(0.055, 0.012)
            iat_std = random.gauss(0.01, 0.003)
            iat_min = random.uniform(0.002, 0.01)
            iat_max = random.uniform(0.15, 0.5)
            
            initial_packet_size = random.choice([512, 536, 558])
            tls_detected = 1.0
            
            # Bridges use non-standard ports, less on 443/9001
            port_443_ratio = random.uniform(0.4, 0.8)
            port_9001_ratio = 0.0  # Bridges avoid standard TOR ports
            
            size_entropy = random.uniform(1.8, 3.0)
            
        elif class_label == 'VPN':
            # VPN traffic characteristics
            duration = random.uniform(5.0, 200.0)
            total_packets = random.randint(50, 400)
            avg_packet_size = random.uniform(400, 1200)  # Larger, varied
            total_bytes = int(total_packets * avg_packet_size)
            
            packets_per_second = total_packets / duration
            bytes_per_second = total_bytes / duration
            
            iat_mean = random.gauss(0.03, 0.015)
            iat_std = random.gauss(0.025, 0.01)
            iat_min = random.uniform(0.0005, 0.005)
            iat_max = random.uniform(0.2, 1.0)
            
            initial_packet_size = random.randint(200, 1400)
            tls_detected = random.choice([0.0, 1.0])
            
            port_443_ratio = random.uniform(0.0, 0.3)
            port_9001_ratio = 0.0
            
            size_entropy = random.uniform(3.5, 5.5)
            
        else:  # NON_TOR
            # Regular internet traffic
            duration = random.uniform(0.5, 100.0)
            total_packets = random.randint(5, 250)
            avg_packet_size = random.uniform(80, 1300)
            total_bytes = int(total_packets * avg_packet_size)
            
            packets_per_second = total_packets / duration
            bytes_per_second = total_bytes / duration
            
            iat_mean = random.uniform(0.001, 0.15)
            iat_std = random.uniform(0.01, 0.12)
            iat_min = random.uniform(0.0001, 0.008)
            iat_max = random.uniform(0.3, 2.5)
            
            initial_packet_size = random.randint(40, 1500)
            tls_detected = random.choice([0.0, 0.0, 1.0])  # Sometimes TLS
            
            port_443_ratio = random.uniform(0.0, 0.7)
            port_9001_ratio = 0.0
            
            size_entropy = random.uniform(4.0, 7.0)  # High entropy
        
        return np.array([
            duration,
            total_packets,
            total_bytes,
            packets_per_second,
            bytes_per_second,
            avg_packet_size,
            iat_mean,
            iat_std,
            iat_min,
            iat_max,
            initial_packet_size,
            tls_detected,
            port_443_ratio,
            port_9001_ratio,
            size_entropy
        ])
    
    def generate_training_data(self, n_samples: int = 3000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate synthetic training data for all classes.
        
        Args:
            n_samples: Total samples (distributed among classes)
            
        Returns:
            (features, labels) arrays
        """
        # Distribution: 40% NON_TOR, 30% TOR_ENTRY_GUARD, 15% TOR_BRIDGE, 15% VPN
        class_distribution = {
            'NON_TOR': int(n_samples * 0.40),
            'TOR_ENTRY_GUARD': int(n_samples * 0.30),
            'TOR_BRIDGE': int(n_samples * 0.15),
            'VPN': int(n_samples * 0.15)
        }
        
        features = []
        labels = []
        
        for class_label, count in class_distribution.items():
            for _ in range(count):
                features.append(self._generate_sample(class_label))
                labels.append(class_label)
        
        # Shuffle
        combined = list(zip(features, labels))
        random.shuffle(combined)
        features, labels = zip(*combined)
        
        return np.array(features), np.array(labels)
    
    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train the 4-class classifier.
        
        Args:
            X: Feature matrix
            y: Class labels (strings)
            test_size: Test split fraction
            
        Returns:
            Training metrics including per-class performance
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn required. Install with: pip install scikit-learn")
        
        # Encode labels
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
        )
        
        # Train
        self.model = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        
        # Overall metrics
        self.training_metrics = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision_weighted': float(precision_score(y_test, y_pred, average='weighted', zero_division=0)),
            'recall_weighted': float(recall_score(y_test, y_pred, average='weighted', zero_division=0)),
            'f1_weighted': float(f1_score(y_test, y_pred, average='weighted', zero_division=0)),
            'train_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        # Per-class metrics
        precision_per_class = precision_score(y_test, y_pred, average=None, zero_division=0)
        recall_per_class = recall_score(y_test, y_pred, average=None, zero_division=0)
        f1_per_class = f1_score(y_test, y_pred, average=None, zero_division=0)
        
        self.per_class_metrics = {}
        for i, class_name in enumerate(self.label_encoder.classes_):
            self.per_class_metrics[class_name] = {
                'precision': float(precision_per_class[i]),
                'recall': float(recall_per_class[i]),
                'f1_score': float(f1_per_class[i])
            }
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        self.training_metrics['confusion_matrix'] = cm.tolist()
        
        self.is_trained = True
        return self.training_metrics
    
    def train_with_synthetic(self, n_samples: int = 3000) -> Dict[str, Any]:
        """
        Train with synthetic data.
        
        Args:
            n_samples: Number of samples
            
        Returns:
            Training metrics
        """
        X, y = self.generate_training_data(n_samples)
        return self.train(X, y)
    
    def predict(self, features: np.ndarray) -> DeepClassificationResult:
        """
        Classify a feature vector.
        
        Args:
            features: 15-element feature vector
            
        Returns:
            DeepClassificationResult with class probabilities
        """
        if not self.is_trained:
            self.train_with_synthetic()
        
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Get prediction and probabilities
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        
        # Decode class name
        traffic_type = self.label_encoder.inverse_transform([prediction])[0]
        confidence = float(max(probabilities))
        
        # Class probabilities
        class_probs = {}
        for i, class_name in enumerate(self.label_encoder.classes_):
            class_probs[class_name] = float(probabilities[i])
        
        return DeepClassificationResult(
            traffic_type=traffic_type,
            confidence=confidence,
            class_probabilities=class_probs
        )
    
    def predict_from_flow(self, flow_features) -> DeepClassificationResult:
        """
        Classify using FlowFeatures object.
        
        Uses rule-based detection with exclusions for known non-TOR traffic.
        Only classifies as TOR when there are strong positive indicators.
        
        Args:
            flow_features: Object with to_feature_vector method
            
        Returns:
            DeepClassificationResult
        """
        # Extract flow info for rule-based detection
        dst_ip = getattr(flow_features, 'dst_ip', '')
        src_ip = getattr(flow_features, 'src_ip', '')
        dst_port = getattr(flow_features, 'dst_port', 0)
        src_port = getattr(flow_features, 'src_port', 0)
        avg_packet_size = getattr(flow_features, 'avg_packet_size', 0)
        tls_detected = getattr(flow_features, 'tls_handshake_detected', False)
        
        # ========== EXCLUSION RULES (Non-TOR traffic) ==========
        
        # Multicast addresses (224.x.x.x - 239.x.x.x)
        if dst_ip.startswith('224.') or dst_ip.startswith('239.'):
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.99,
                class_probabilities={'NON_TOR': 0.99, 'TOR_ENTRY_GUARD': 0.00, 'TOR_BRIDGE': 0.00, 'VPN': 0.01}
            )
        
        # Broadcast addresses
        if dst_ip.startswith('255.') or dst_ip.endswith('.255'):
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.99,
                class_probabilities={'NON_TOR': 0.99, 'TOR_ENTRY_GUARD': 0.00, 'TOR_BRIDGE': 0.00, 'VPN': 0.01}
            )
        
        # Link-local addresses (169.254.x.x)
        if dst_ip.startswith('169.254.'):
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.99,
                class_probabilities={'NON_TOR': 0.99, 'TOR_ENTRY_GUARD': 0.00, 'TOR_BRIDGE': 0.00, 'VPN': 0.01}
            )
        
        # DNS traffic (port 53)
        if dst_port == 53 or src_port == 53:
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.95,
                class_probabilities={'NON_TOR': 0.95, 'TOR_ENTRY_GUARD': 0.02, 'TOR_BRIDGE': 0.02, 'VPN': 0.01}
            )
        
        # mDNS traffic (port 5353)
        if dst_port == 5353 or src_port == 5353:
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.99,
                class_probabilities={'NON_TOR': 0.99, 'TOR_ENTRY_GUARD': 0.00, 'TOR_BRIDGE': 0.00, 'VPN': 0.01}
            )
        
        # LLMNR traffic (port 5355)
        if dst_port == 5355 or src_port == 5355:
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.99,
                class_probabilities={'NON_TOR': 0.99, 'TOR_ENTRY_GUARD': 0.00, 'TOR_BRIDGE': 0.00, 'VPN': 0.01}
            )
        
        # SSDP/UPnP traffic (port 1900)
        if dst_port == 1900 or src_port == 1900:
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.99,
                class_probabilities={'NON_TOR': 0.99, 'TOR_ENTRY_GUARD': 0.00, 'TOR_BRIDGE': 0.00, 'VPN': 0.01}
            )
        
        # WS-Discovery (port 3702)
        if dst_port == 3702 or src_port == 3702:
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.99,
                class_probabilities={'NON_TOR': 0.99, 'TOR_ENTRY_GUARD': 0.00, 'TOR_BRIDGE': 0.00, 'VPN': 0.01}
            )
        
        # NetBIOS traffic (ports 137, 138, 139)
        if dst_port in [137, 138, 139] or src_port in [137, 138, 139]:
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.99,
                class_probabilities={'NON_TOR': 0.99, 'TOR_ENTRY_GUARD': 0.00, 'TOR_BRIDGE': 0.00, 'VPN': 0.01}
            )
        
        # Private network internal traffic (10.x.x.x)
        # Only exclude if NOT going to TOR ports
        if dst_ip.startswith('10.') and dst_port not in [9001, 9030, 9050, 9150, 9051]:
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.90,
                class_probabilities={'NON_TOR': 0.90, 'TOR_ENTRY_GUARD': 0.03, 'TOR_BRIDGE': 0.05, 'VPN': 0.02}
            )
        
        # Private network (192.168.x.x) - exclude unless TOR ports
        if dst_ip.startswith('192.168.') and dst_port not in [9001, 9030, 9050, 9150, 9051]:
            return DeepClassificationResult(
                traffic_type='NON_TOR',
                confidence=0.90,
                class_probabilities={'NON_TOR': 0.90, 'TOR_ENTRY_GUARD': 0.03, 'TOR_BRIDGE': 0.05, 'VPN': 0.02}
            )
        
        # ========== TOR DETECTION RULES ==========
        
        # Known TOR relay prefixes (only definitive ones)
        tor_prefixes = [
            '185.220.100.', '185.220.101.', '185.220.102.', '185.220.103.', '185.220.104.',
            '199.249.230.', '199.249.231.', '162.247.72.', '162.247.73.',
            '89.234.157.', '87.118.122.', '23.129.64.', '104.244.72.',
            '178.17.170.', '178.17.171.', '193.218.118.',
        ]
        
        # Check localhost for SOCKS
        is_localhost = dst_ip.startswith('127.') or src_ip.startswith('127.')
        is_socks_port = dst_port in [9050, 9150, 9051] or src_port in [9050, 9150, 9051]
        
        # Rule 1: Localhost SOCKS = TOR_ENTRY_GUARD (via SOCKS)
        if is_localhost and is_socks_port:
            return DeepClassificationResult(
                traffic_type='TOR_ENTRY_GUARD',
                confidence=0.95,
                class_probabilities={'NON_TOR': 0.02, 'TOR_ENTRY_GUARD': 0.95, 'TOR_BRIDGE': 0.02, 'VPN': 0.01}
            )
        
        # Rule 2: TOR ORPorts = TOR_ENTRY_GUARD
        if dst_port in [9001, 9030]:
            return DeepClassificationResult(
                traffic_type='TOR_ENTRY_GUARD',
                confidence=0.92,
                class_probabilities={'NON_TOR': 0.03, 'TOR_ENTRY_GUARD': 0.92, 'TOR_BRIDGE': 0.03, 'VPN': 0.02}
            )
        
        # Rule 3: Known TOR relay IP = TOR_ENTRY_GUARD
        if any(dst_ip.startswith(p) for p in tor_prefixes):
            confidence = 0.88
            if tls_detected:
                confidence = 0.92
            return DeepClassificationResult(
                traffic_type='TOR_ENTRY_GUARD',
                confidence=confidence,
                class_probabilities={'NON_TOR': 0.02, 'TOR_ENTRY_GUARD': confidence, 'TOR_BRIDGE': 0.05, 'VPN': 0.03}
            )
        
        # Rule 4: VPN ports = VPN
        if dst_port in [1194, 51820, 500, 4500, 1701, 1723]:
            return DeepClassificationResult(
                traffic_type='VPN',
                confidence=0.85,
                class_probabilities={'NON_TOR': 0.08, 'TOR_ENTRY_GUARD': 0.02, 'TOR_BRIDGE': 0.05, 'VPN': 0.85}
            )
        
        # ========== DEFAULT: NON_TOR ==========
        # If no rules matched, classify as NON_TOR (not TOR)
        # DO NOT use ML - it produces too many false positives
        return DeepClassificationResult(
            traffic_type='NON_TOR',
            confidence=0.80,
            class_probabilities={'NON_TOR': 0.80, 'TOR_ENTRY_GUARD': 0.08, 'TOR_BRIDGE': 0.08, 'VPN': 0.04}
        )
    
    def predict_from_flow_ml(self, flow_features) -> DeepClassificationResult:
        """ML-only prediction (use predict_from_flow for rule-based detection)."""
        features = flow_features.to_feature_vector()
        return self.predict(features)
    
    def get_per_class_metrics(self) -> Dict[str, Dict[str, float]]:
        """Get per-class performance metrics."""
        return self.per_class_metrics
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores."""
        if not self.is_trained or self.model is None:
            return {}
        
        importances = self.model.feature_importances_
        return {
            name: float(imp)
            for name, imp in zip(self.FEATURE_NAMES, importances)
        }
    
    def get_classes(self) -> List[str]:
        """Get list of class names."""
        if self.label_encoder:
            return list(self.label_encoder.classes_)
        return self.CLASSES
