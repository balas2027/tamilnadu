"""
Automated Alert System.

Real-time monitoring and alerting for suspicious TOR traffic patterns:
- Hidden Service connection detection
- Botnet-like behavior patterns
- Unusual traffic volumes
- Geographic anomalies

Integrates with SIEM systems via JSON log export.
"""

import time
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
from enum import Enum
from collections import deque
import threading


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertType(Enum):
    """Types of security alerts."""
    HIDDEN_SERVICE = "HIDDEN_SERVICE_CONNECTION"
    BOTNET_PATTERN = "BOTNET_LIKE_BEHAVIOR"
    HIGH_VOLUME = "HIGH_VOLUME_TRAFFIC"
    UNUSUAL_TIMING = "UNUSUAL_TIMING_PATTERN"
    NEW_ENTRY_GUARD = "NEW_ENTRY_GUARD"
    EXIT_NODE_ANOMALY = "EXIT_NODE_ANOMALY"
    CORRELATION_MATCH = "CORRELATION_ATTACK_MATCH"
    ORIGIN_IDENTIFIED = "ORIGIN_IP_IDENTIFIED"


@dataclass
class Alert:
    """Security alert object."""
    alert_id: str
    alert_type: AlertType
    severity: AlertSeverity
    timestamp: float
    title: str
    description: str
    
    # Context
    source_ip: str = ""
    destination_ip: str = ""
    circuit_id: str = ""
    confidence: float = 0.0
    
    # Status
    acknowledged: bool = False
    
    # Additional data
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'alert_id': self.alert_id,
            'type': self.alert_type.value,
            'severity': self.severity.value,
            'timestamp': self.timestamp,
            'timestamp_formatted': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp)),
            'title': self.title,
            'description': self.description,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'circuit_id': self.circuit_id,
            'confidence': round(self.confidence, 3),
            'acknowledged': self.acknowledged,
            'metadata': self.metadata
        }
    
    def to_siem_format(self) -> str:
        """Format alert for SIEM ingestion (JSON line)."""
        siem_data = {
            **self.to_dict(),
            'event_type': 'SECURITY_ALERT',
            'product': 'RT-TTA',
            'vendor': 'TOR-Forensics'
        }
        return json.dumps(siem_data)


@dataclass
class AlertThreshold:
    """Configurable alert threshold."""
    name: str
    value: float
    operator: str  # "gt", "lt", "eq", "gte", "lte"
    severity: AlertSeverity
    
    def check(self, actual_value: float) -> bool:
        """Check if threshold is exceeded."""
        ops = {
            'gt': lambda a, b: a > b,
            'lt': lambda a, b: a < b,
            'eq': lambda a, b: a == b,
            'gte': lambda a, b: a >= b,
            'lte': lambda a, b: a <= b
        }
        return ops.get(self.operator, lambda a, b: False)(actual_value, self.value)


class AlertSystem:
    """
    Real-time Alert System for TOR Traffic Analysis.
    
    Features:
    - Configurable alert thresholds
    - Multiple alert types
    - SIEM integration via log export
    - Alert history and statistics
    """
    
    # Default thresholds
    DEFAULT_THRESHOLDS = {
        'hidden_service_confidence': AlertThreshold("HS Confidence", 0.7, "gte", AlertSeverity.HIGH),
        'botnet_regularity': AlertThreshold("Botnet IAT CV", 0.3, "lte", AlertSeverity.CRITICAL),
        'correlation_score': AlertThreshold("Correlation Score", 0.65, "gte", AlertSeverity.HIGH),
        'origin_confidence': AlertThreshold("Origin Confidence", 0.8, "gte", AlertSeverity.MEDIUM),
        'traffic_volume_mb': AlertThreshold("Traffic Volume (MB)", 100, "gte", AlertSeverity.LOW)
    }
    
    def __init__(self, 
                 log_dir: str = "./alerts",
                 max_history: int = 1000):
        """
        Initialize alert system.
        
        Args:
            log_dir: Directory for alert logs
            max_history: Maximum alerts to keep in memory
        """
        self.log_dir = log_dir
        self.max_history = max_history
        self._alerts: deque = deque(maxlen=max_history)
        self._thresholds = self.DEFAULT_THRESHOLDS.copy()
        self._callbacks: List[Callable] = []
        self._alert_count = 0
        self._lock = threading.Lock()
        
        # Ensure log directory exists
        os.makedirs(log_dir, exist_ok=True)
        
        # Open log file
        self._log_file = os.path.join(log_dir, f"alerts_{int(time.time())}.jsonl")
    
    def set_threshold(self, name: str, threshold: AlertThreshold):
        """Set or update an alert threshold."""
        self._thresholds[name] = threshold
    
    def register_callback(self, callback: Callable[[Alert], None]):
        """Register callback to be called on new alerts."""
        self._callbacks.append(callback)
    
    def create_alert(self,
                     alert_type: AlertType,
                     severity: AlertSeverity,
                     title: str,
                     description: str,
                     **kwargs) -> Alert:
        """
        Create and store a new alert.
        
        Returns:
            Created Alert object
        """
        with self._lock:
            self._alert_count += 1
            alert_id = f"ALERT-{int(time.time())}-{self._alert_count:04d}"
        
        alert = Alert(
            alert_id=alert_id,
            alert_type=alert_type,
            severity=severity,
            timestamp=time.time(),
            title=title,
            description=description,
            source_ip=kwargs.get('source_ip', ''),
            destination_ip=kwargs.get('destination_ip', ''),
            circuit_id=kwargs.get('circuit_id', ''),
            confidence=kwargs.get('confidence', 0.0),
            metadata=kwargs.get('metadata', {})
        )
        
        self._alerts.append(alert)
        self._log_alert(alert)
        self._notify_callbacks(alert)
        
        return alert
    
    def _log_alert(self, alert: Alert):
        """Write alert to log file (SIEM format)."""
        try:
            with open(self._log_file, 'a') as f:
                f.write(alert.to_siem_format() + '\n')
        except Exception as e:
            print(f"Failed to log alert: {e}")
    
    def _notify_callbacks(self, alert: Alert):
        """Notify all registered callbacks."""
        for callback in self._callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Alert callback error: {e}")
    
    # Pre-built alert generators
    
    def alert_hidden_service_connection(self,
                                         origin_ip: str,
                                         circuit_id: str,
                                         purpose: str,
                                         confidence: float) -> Alert:
        """Create alert for Hidden Service connection detection."""
        return self.create_alert(
            alert_type=AlertType.HIDDEN_SERVICE,
            severity=AlertSeverity.HIGH,
            title="Hidden Service Connection Detected",
            description=f"Device at {origin_ip} connected to TOR Hidden Service via Circuit #{circuit_id}. "
                       f"Purpose: {purpose}. Confidence: {confidence:.1%}",
            source_ip=origin_ip,
            circuit_id=circuit_id,
            confidence=confidence,
            metadata={'purpose': purpose}
        )
    
    def alert_botnet_pattern(self,
                             origin_ip: str,
                             iat_cv: float,
                             fixed_sizes: List[int]) -> Alert:
        """Create alert for botnet-like behavior pattern."""
        return self.create_alert(
            alert_type=AlertType.BOTNET_PATTERN,
            severity=AlertSeverity.CRITICAL,
            title="Botnet-Like Behavior Detected",
            description=f"Device at {origin_ip} exhibits highly regular communication patterns. "
                       f"IAT CV: {iat_cv:.3f} (below threshold). Fixed packet sizes: {fixed_sizes}",
            source_ip=origin_ip,
            confidence=1 - iat_cv,  # Lower CV = higher confidence
            metadata={'iat_cv': iat_cv, 'fixed_sizes': fixed_sizes}
        )
    
    def alert_correlation_match(self,
                                 entry_ip: str,
                                 exit_ip: str,
                                 origin_ip: str,
                                 score: float) -> Alert:
        """Create alert for correlation attack match."""
        return self.create_alert(
            alert_type=AlertType.CORRELATION_MATCH,
            severity=AlertSeverity.HIGH,
            title="Traffic Correlation Match Detected",
            description=f"Entry-Exit traffic correlation identified. Origin: {origin_ip}. "
                       f"Entry Guard: {entry_ip}, Exit Node: {exit_ip}. Correlation: {score:.1%}",
            source_ip=origin_ip,
            destination_ip=exit_ip,
            confidence=score,
            metadata={'entry_ip': entry_ip, 'exit_ip': exit_ip}
        )
    
    def alert_origin_identified(self,
                                 origin_ip: str,
                                 entry_guard: str,
                                 ccs: float) -> Alert:
        """Create alert for successful origin identification."""
        return self.create_alert(
            alert_type=AlertType.ORIGIN_IDENTIFIED,
            severity=AlertSeverity.MEDIUM if ccs < 0.8 else AlertSeverity.HIGH,
            title="TOR Traffic Origin Identified",
            description=f"Successfully traced TOR traffic to Origin IP: {origin_ip}. "
                       f"Entry Guard: {entry_guard}. Composite Confidence: {ccs:.1%}",
            source_ip=origin_ip,
            destination_ip=entry_guard,
            confidence=ccs,
            metadata={'ccs': ccs, 'entry_guard': entry_guard}
        )
    
    # Analysis methods
    
    def check_for_alerts(self, flow_data: Dict) -> List[Alert]:
        """
        Analyze flow data and generate appropriate alerts.
        
        Args:
            flow_data: Dictionary containing flow analysis data
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        # Check Hidden Service
        purpose = flow_data.get('purpose', '')
        if 'HS_' in purpose or 'REND' in purpose:
            confidence = flow_data.get('composite_confidence_score', flow_data.get('confidence', 0.7))
            if self._thresholds['hidden_service_confidence'].check(confidence):
                alert = self.alert_hidden_service_connection(
                    origin_ip=flow_data.get('probable_origin_ip', 'Unknown'),
                    circuit_id=flow_data.get('circuit_id', ''),
                    purpose=purpose,
                    confidence=confidence
                )
                alerts.append(alert)
        
        # Check botnet patterns
        iat_cv = flow_data.get('iat_cv', 1.0)
        if self._thresholds['botnet_regularity'].check(iat_cv):
            alert = self.alert_botnet_pattern(
                origin_ip=flow_data.get('probable_origin_ip', 'Unknown'),
                iat_cv=iat_cv,
                fixed_sizes=flow_data.get('fixed_packet_sizes', [])
            )
            alerts.append(alert)
        
        # Check origin identification
        ccs = flow_data.get('composite_confidence_score', 0)
        origin_ip = flow_data.get('probable_origin_ip', '')
        if origin_ip and self._thresholds['origin_confidence'].check(ccs):
            alert = self.alert_origin_identified(
                origin_ip=origin_ip,
                entry_guard=flow_data.get('entry_guard_ip', ''),
                ccs=ccs
            )
            alerts.append(alert)
        
        return alerts
    
    def get_alerts(self, 
                   severity: AlertSeverity = None,
                   alert_type: AlertType = None,
                   limit: int = 100) -> List[Alert]:
        """Get alerts with optional filtering."""
        alerts = list(self._alerts)
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        
        # Return most recent first
        return sorted(alerts, key=lambda a: -a.timestamp)[:limit]
    
    def get_statistics(self) -> Dict:
        """Get alert statistics."""
        if not self._alerts:
            return {'total': 0}
        
        alerts = list(self._alerts)
        
        by_severity = {}
        for sev in AlertSeverity:
            by_severity[sev.value] = sum(1 for a in alerts if a.severity == sev)
        
        by_type = {}
        for at in AlertType:
            count = sum(1 for a in alerts if a.alert_type == at)
            if count > 0:
                by_type[at.value] = count
        
        return {
            'total': len(alerts),
            'unacknowledged': sum(1 for a in alerts if not a.acknowledged),
            'by_severity': by_severity,
            'by_type': by_type,
            'log_file': self._log_file
        }
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged."""
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False
    
    def export_alerts_json(self, filepath: str = None) -> str:
        """Export all alerts to JSON file."""
        if filepath is None:
            filepath = os.path.join(self.log_dir, f"alerts_export_{int(time.time())}.json")
        
        export_data = {
            'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': self.get_statistics(),
            'alerts': [a.to_dict() for a in self._alerts]
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        return filepath


# Singleton instance
_alert_system: Optional[AlertSystem] = None


def get_alert_system() -> AlertSystem:
    """Get singleton alert system instance."""
    global _alert_system
    if _alert_system is None:
        _alert_system = AlertSystem()
    return _alert_system
