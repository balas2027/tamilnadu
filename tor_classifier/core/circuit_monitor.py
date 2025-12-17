"""
TOR Circuit Monitor.

Connects to the local TOR daemon to monitor active circuits
and show the Entry → Middle → Exit path for traffic.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Try to import stem for TOR control
try:
    from stem import CircStatus
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False


@dataclass
class TorRelay:
    """Information about a TOR relay in a circuit."""
    fingerprint: str
    nickname: str
    ip_address: str
    or_port: int
    country: str = "Unknown"
    is_entry: bool = False
    is_middle: bool = False
    is_exit: bool = False
    bandwidth: int = 0


@dataclass 
class TorCircuit:
    """A TOR circuit (Entry → Middle → Exit)."""
    circuit_id: str
    status: str
    purpose: str
    path: List[TorRelay]
    created_time: float
    
    @property
    def entry_guard(self) -> Optional[TorRelay]:
        """Get entry guard (first hop)."""
        if len(self.path) >= 1:
            relay = self.path[0]
            relay.is_entry = True
            return relay
        return None
    
    @property
    def middle_relay(self) -> Optional[TorRelay]:
        """Get middle relay (second hop)."""
        if len(self.path) >= 2:
            relay = self.path[1]
            relay.is_middle = True
            return relay
        return None
    
    @property
    def exit_node(self) -> Optional[TorRelay]:
        """Get exit node (last hop)."""
        if len(self.path) >= 3:
            relay = self.path[-1]
            relay.is_exit = True
            return relay
        return None
    
    def to_dict(self) -> Dict:
        return {
            'circuit_id': self.circuit_id,
            'status': self.status,
            'purpose': self.purpose,
            'hops': len(self.path),
            'entry': self.path[0].nickname if len(self.path) >= 1 else None,
            'middle': self.path[1].nickname if len(self.path) >= 2 else None,
            'exit': self.path[-1].nickname if len(self.path) >= 3 else None,
        }


@dataclass
class TorStream:
    """An active stream through TOR."""
    stream_id: str
    circuit_id: str
    target: str
    status: str
    
    def to_dict(self) -> Dict:
        return {
            'stream_id': self.stream_id,
            'circuit_id': self.circuit_id,
            'target': self.target,
            'status': self.status
        }


class TorCircuitMonitor:
    """
    Monitor TOR circuits and streams in real-time.
    
    Connects to the local TOR Control Port to fetch:
    - Active circuits and their relay paths
    - Active streams and their destinations
    - Entry Guard, Middle Relay, Exit Node for each circuit
    """
    
    def __init__(self, control_port: int = 9051, password: str = None):
        """
        Initialize circuit monitor.
        
        Args:
            control_port: TOR control port (default 9051)
            password: Optional password for authentication
        """
        self.control_port = control_port
        self.password = password
        self._controller: Optional['Controller'] = None
        self._connected = False
        self._circuits: List[TorCircuit] = []
        self._streams: List[TorStream] = []
    
    def connect(self) -> bool:
        """Connect to TOR control port."""
        if not STEM_AVAILABLE:
            print("❌ stem library not available")
            return False
        
        try:
            self._controller = Controller.from_port(port=self.control_port)
            
            # Try cookie authentication first
            try:
                self._controller.authenticate()
            except Exception:
                if self.password:
                    self._controller.authenticate(password=self.password)
                else:
                    raise
            
            self._connected = True
            print(f"✅ Connected to TOR Control Port {self.control_port}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to connect to TOR: {e}")
            self._connected = False
            return False
    
    def is_connected(self) -> bool:
        """Check if connected to TOR."""
        return self._connected and self._controller is not None
    
    def get_circuits(self) -> List[TorCircuit]:
        """Get all active TOR circuits."""
        if not self.is_connected():
            return []
        
        circuits = []
        
        try:
            for circ in self._controller.get_circuits():
                if circ.status != CircStatus.BUILT:
                    continue
                
                path = []
                for fp, nickname in circ.path:
                    # Get relay info from consensus
                    relay = TorRelay(
                        fingerprint=fp,
                        nickname=nickname,
                        ip_address="",
                        or_port=0
                    )
                    
                    # Try to get more info
                    try:
                        ns = self._controller.get_network_status(fp)
                        if ns:
                            relay.ip_address = ns.address
                            relay.or_port = ns.or_port
                    except:
                        pass
                    
                    path.append(relay)
                
                circuit = TorCircuit(
                    circuit_id=str(circ.id),
                    status=str(circ.status),
                    purpose=str(circ.purpose) if circ.purpose else "GENERAL",
                    path=path,
                    created_time=time.time()
                )
                circuits.append(circuit)
            
            self._circuits = circuits
            
        except Exception as e:
            print(f"Error getting circuits: {e}")
        
        return circuits
    
    def get_streams(self) -> List[TorStream]:
        """Get all active streams."""
        if not self.is_connected():
            return []
        
        streams = []
        
        try:
            for stream in self._controller.get_streams():
                s = TorStream(
                    stream_id=str(stream.id),
                    circuit_id=str(stream.circ_id) if stream.circ_id else "0",
                    target=stream.target or "",
                    status=str(stream.status)
                )
                streams.append(s)
            
            self._streams = streams
            
        except Exception as e:
            print(f"Error getting streams: {e}")
        
        return streams
    
    def get_entry_guards(self) -> List[TorRelay]:
        """Get all unique entry guards from active circuits."""
        circuits = self.get_circuits()
        guards = {}
        
        for circ in circuits:
            if circ.entry_guard:
                g = circ.entry_guard
                guards[g.fingerprint] = g
        
        return list(guards.values())
    
    def get_circuit_for_stream(self, stream_id: str) -> Optional[TorCircuit]:
        """Get the circuit used by a specific stream."""
        for stream in self._streams:
            if stream.stream_id == stream_id:
                for circ in self._circuits:
                    if circ.circuit_id == stream.circuit_id:
                        return circ
        return None
    
    def get_status(self) -> Dict:
        """Get current TOR status."""
        if not self.is_connected():
            return {
                'connected': False,
                'message': 'Not connected to TOR Control Port'
            }
        
        try:
            circuits = self.get_circuits()
            streams = self.get_streams()
            guards = self.get_entry_guards()
            
            return {
                'connected': True,
                'active_circuits': len(circuits),
                'active_streams': len(streams),
                'entry_guards_used': len(guards),
                'circuits': [c.to_dict() for c in circuits],
                'streams': [s.to_dict() for s in streams]
            }
            
        except Exception as e:
            return {
                'connected': False,
                'message': str(e)
            }
    
    def close(self):
        """Close connection to TOR."""
        if self._controller:
            try:
                self._controller.close()
            except:
                pass
        self._connected = False


# Singleton instance
_monitor_instance: Optional[TorCircuitMonitor] = None


def get_circuit_monitor(control_port: int = 9051) -> TorCircuitMonitor:
    """Get singleton circuit monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = TorCircuitMonitor(control_port)
    return _monitor_instance
