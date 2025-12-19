"""
Global Network Listener Module.

Scapy-based packet capture for network-wide TOR traffic monitoring.
Captures all traffic on a network interface and feeds it to the correlation engine.
"""

import time
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from collections import deque

# Try to import scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[GlobalListener] Warning: Scapy not available. Install with: pip install scapy")


@dataclass
class PacketInfo:
    """Information about a captured packet."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    timestamp: float
    is_tls: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'size': self.size,
            'timestamp': self.timestamp,
            'is_tls': self.is_tls
        }


class GlobalListener:
    """
    Global Network Packet Listener.
    
    Captures all network traffic on an interface and provides
    real-time packet callbacks for TOR detection.
    
    Requires administrator/root privileges to capture packets.
    """
    
    def __init__(self, interface: Optional[str] = None):
        """
        Initialize global listener.
        
        Args:
            interface: Network interface to capture on (None for default)
        """
        self.interface = interface
        self._running = False
        self._capture_thread: Optional[threading.Thread] = None
        self._packet_callbacks: List[Callable[[PacketInfo], None]] = []
        self._packets: deque = deque(maxlen=10000)  # Buffer last 10k packets
        self._packet_count = 0
        self._start_time: float = 0
        self._stop_event = threading.Event()
    
    @staticmethod
    def get_available_interfaces() -> List[str]:
        """
        Get list of available network interfaces.
        
        Returns:
            List of interface names
        """
        if not SCAPY_AVAILABLE:
            return []
        
        try:
            interfaces = get_if_list()
            return interfaces
        except Exception as e:
            print(f"[GlobalListener] Error getting interfaces: {e}")
            return []
    
    @staticmethod
    def get_default_interface() -> Optional[str]:
        """Get the default network interface."""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            return conf.iface
        except:
            return None
    
    def on_packet(self, callback: Callable[[PacketInfo], None]):
        """
        Register a callback for packet events.
        
        Args:
            callback: Function called for each captured packet
        """
        self._packet_callbacks.append(callback)
    
    def _parse_packet(self, pkt) -> Optional[PacketInfo]:
        """Parse a scapy packet into PacketInfo."""
        try:
            if not pkt.haslayer(IP):
                return None
            
            ip_layer = pkt[IP]
            src_port = 0
            dst_port = 0
            protocol = "OTHER"
            is_tls = False
            
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
                
                # Check for TLS/SSL (port 443, 9001, etc.)
                if dst_port in [443, 9001] or src_port in [443, 9001]:
                    is_tls = True
                    
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
            
            return PacketInfo(
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=len(pkt),
                timestamp=float(pkt.time),
                is_tls=is_tls
            )
            
        except Exception as e:
            return None
    
    def _packet_handler(self, pkt):
        """Internal packet handler for sniff callback."""
        packet_info = self._parse_packet(pkt)
        if packet_info:
            self._packet_count += 1
            self._packets.append(packet_info)
            
            # Call registered callbacks
            for callback in self._packet_callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    print(f"[GlobalListener] Callback error: {e}")
    
    def _capture_loop(self, duration: Optional[float] = None, filter_expr: Optional[str] = None):
        """Main capture loop running in separate thread."""
        try:
            # Build filter for performance (TCP and UDP for TOR detection)
            # TOR uses TCP, but capturing UDP helps with overall traffic analysis
            bpf_filter = filter_expr or "tcp or udp"
            
            print(f"[GlobalListener] Starting capture on {self.interface or 'default'} with filter: {bpf_filter}")
            print("[GlobalListener] Promiscuous mode: ENABLED (required for network-wide capture)")
            
            # NOTE: promisc=True is CRITICAL for seeing traffic from other devices
            # Requires Npcap installed with "WinPcap API-compatible Mode" on Windows
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=0,  # Don't store packets in memory
                filter=bpf_filter,
                promisc=True,  # ENABLE PROMISCUOUS MODE for network-wide capture
                stop_filter=lambda x: self._stop_event.is_set(),
                timeout=duration
            )
            
        except PermissionError:
            print("[GlobalListener] ERROR: Permission denied. Run as Administrator!")
        except Exception as e:
            print(f"[GlobalListener] Capture error: {e}")
        finally:
            self._running = False
    
    def start(self, duration: Optional[float] = None, filter_expr: Optional[str] = None):
        """
        Start packet capture in background thread.
        
        Args:
            duration: Capture duration in seconds (None = unlimited)
            filter_expr: BPF filter expression (default: "tcp")
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet capture. Install with: pip install scapy")
        
        if self._running:
            print("[GlobalListener] Already capturing")
            return
        
        self._running = True
        self._start_time = time.time()
        self._stop_event.clear()
        
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(duration, filter_expr),
            daemon=True
        )
        self._capture_thread.start()
        
        print(f"[GlobalListener] Capture started")
    
    def stop(self):
        """Stop packet capture."""
        if not self._running:
            return
        
        self._stop_event.set()
        self._running = False
        
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2.0)
        
        print(f"[GlobalListener] Capture stopped. Total packets: {self._packet_count}")
    
    def is_running(self) -> bool:
        """Check if capture is running."""
        return self._running
    
    def get_packets(self, count: Optional[int] = None) -> List[PacketInfo]:
        """
        Get captured packets.
        
        Args:
            count: Number of recent packets to return (None = all buffered)
            
        Returns:
            List of PacketInfo objects
        """
        if count is None:
            return list(self._packets)
        return list(self._packets)[-count:]
    
    def get_stats(self) -> Dict:
        """Get capture statistics."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        return {
            'is_running': self._running,
            'packet_count': self._packet_count,
            'elapsed_seconds': round(elapsed, 2),
            'packets_per_second': round(self._packet_count / elapsed, 2) if elapsed > 0 else 0,
            'buffer_size': len(self._packets),
            'interface': self.interface or 'default'
        }
    
    def clear(self):
        """Clear captured packets."""
        self._packets.clear()
        self._packet_count = 0


def create_global_listener(interface: Optional[str] = None) -> GlobalListener:
    """
    Factory function to create a GlobalListener.
    
    Args:
        interface: Network interface to capture on
        
    Returns:
        GlobalListener instance
    """
    return GlobalListener(interface)
