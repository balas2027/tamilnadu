"""
Stream Ingester Module.

Handles traffic capture from PCAP files, live network interfaces,
and provides synthetic data generation for testing and demonstration.
"""

import random
import time
import threading
from dataclasses import dataclass
from typing import List, Dict, Optional, Generator, Any, Callable
from pathlib import Path

# Try to import scapy, but make it optional
try:
    from scapy.all import rdpcap, sniff, IP, TCP, UDP, Raw, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class PacketInfo:
    """Represents a single packet's key information."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    timestamp: float
    tls: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'size': self.size,
            'timestamp': self.timestamp,
            'tls': self.tls
        }


class LiveCaptureSession:
    """
    Manages a live packet capture session.
    
    Runs packet capture in a separate thread and provides
    callbacks for real-time packet processing.
    """
    
    def __init__(self, interface: str = None, packet_callback: Callable = None):
        """
        Initialize live capture session.
        
        Args:
            interface: Network interface to capture on (None for default)
            packet_callback: Function called for each captured packet
        """
        self.interface = interface
        self.packet_callback = packet_callback
        self.packets: List[PacketInfo] = []
        self.is_running = False
        self._stop_flag = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self.packet_count = 0
        self.start_time: Optional[float] = None
        
    def _parse_packet(self, pkt) -> Optional[PacketInfo]:
        """Parse a scapy packet into PacketInfo."""
        try:
            if IP not in pkt:
                return None
            
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            size = len(pkt)
            timestamp = float(pkt.time) if hasattr(pkt, 'time') else time.time()
            
            # Determine protocol and ports
            if TCP in pkt:
                protocol = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                # Check for TLS (port 443 or TLS handshake)
                tls = dst_port == 443 or src_port == 443
                if Raw in pkt:
                    try:
                        payload = bytes(pkt[Raw].load)
                        # TLS handshake starts with 0x16 (22)
                        if len(payload) > 0 and payload[0] == 0x16:
                            tls = True
                    except:
                        pass
            elif UDP in pkt:
                protocol = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                tls = False
            else:
                return None
            
            return PacketInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=size,
                timestamp=timestamp,
                tls=tls
            )
        except Exception:
            return None
    
    def _packet_handler(self, pkt):
        """Internal packet handler for sniff callback."""
        packet_info = self._parse_packet(pkt)
        if packet_info:
            self.packets.append(packet_info)
            self.packet_count += 1
            
            if self.packet_callback:
                try:
                    self.packet_callback(packet_info)
                except Exception:
                    pass
    
    def _capture_loop(self, count: int = 0, timeout: int = None, filter_expr: str = None):
        """Main capture loop running in separate thread."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                count=count if count > 0 else 0,
                timeout=timeout,
                filter=filter_expr,
                stop_filter=lambda x: self._stop_flag.is_set(),
                store=False
            )
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            self.is_running = False
    
    def start(self, count: int = 0, timeout: int = None, filter_expr: str = None):
        """
        Start live packet capture in background thread.
        
        Args:
            count: Number of packets to capture (0 = unlimited)
            timeout: Capture timeout in seconds (None = no timeout)
            filter_expr: BPF filter expression (e.g., "tcp port 443")
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for live capture. Install with: pip install scapy")
        
        if self.is_running:
            return
        
        self.is_running = True
        self.start_time = time.time()
        self._stop_flag.clear()
        self.packets.clear()
        self.packet_count = 0
        
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(count, timeout, filter_expr),
            daemon=True
        )
        self._capture_thread.start()
    
    def stop(self):
        """Stop the live capture session."""
        self._stop_flag.set()
        self.is_running = False
        
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2.0)
    
    def get_packets(self) -> List[PacketInfo]:
        """Get all captured packets."""
        return self.packets.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {
            'packet_count': self.packet_count,
            'elapsed_time': elapsed,
            'packets_per_second': self.packet_count / elapsed if elapsed > 0 else 0,
            'is_running': self.is_running,
            'interface': self.interface
        }


class StreamIngester:
    """
    Ingests network traffic from various sources.
    
    Supports:
    - PCAP file parsing (requires scapy)
    - Live packet capture (requires scapy)
    - Synthetic data generation for testing
    """
    
    # Known TOR relay prefixes for synthetic data
    TOR_RELAY_IPS = [
        '185.220.100.240',
        '185.220.101.1',
        '199.249.230.110',
        '162.247.72.199',
        '89.234.157.254',
        '87.118.122.30',
        '104.244.72.115',
    ]
    
    # Normal IPs for synthetic non-TOR traffic
    NORMAL_IPS = [
        '142.250.185.206',  # google.com
        '151.101.1.140',    # reddit.com
        '104.16.100.29',    # cloudflare.com
        '13.107.42.14',     # microsoft.com
        '157.240.1.35',     # facebook.com
    ]
    
    def __init__(self):
        """Initialize Stream Ingester."""
        self.packets: List[PacketInfo] = []
        self.live_session: Optional[LiveCaptureSession] = None
    
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
        except Exception:
            return []
    
    @staticmethod
    def get_default_interface() -> Optional[str]:
        """Get the default network interface."""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            return conf.iface
        except Exception:
            return None
    
    def start_live_capture(self, 
                           interface: str = None,
                           packet_callback: Callable = None,
                           count: int = 0,
                           timeout: int = None,
                           filter_expr: str = None) -> LiveCaptureSession:
        """
        Start live packet capture.
        
        Args:
            interface: Network interface (None for default)
            packet_callback: Function called for each packet
            count: Number of packets to capture (0 = unlimited)
            timeout: Capture timeout in seconds
            filter_expr: BPF filter (e.g., "tcp port 443")
            
        Returns:
            LiveCaptureSession object
            
        Example:
            ingester = StreamIngester()
            session = ingester.start_live_capture(
                interface="eth0",
                packet_callback=lambda p: print(f"Got packet: {p.src_ip}"),
                timeout=30
            )
            # ... do other work ...
            session.stop()
            packets = session.get_packets()
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for live capture. Install with: pip install scapy")
        
        # Stop any existing session
        if self.live_session and self.live_session.is_running:
            self.live_session.stop()
        
        # Create new session
        self.live_session = LiveCaptureSession(
            interface=interface,
            packet_callback=packet_callback
        )
        
        # Start capture
        self.live_session.start(count=count, timeout=timeout, filter_expr=filter_expr)
        
        return self.live_session
    
    def stop_live_capture(self) -> List[PacketInfo]:
        """
        Stop live capture and return captured packets.
        
        Returns:
            List of captured PacketInfo objects
        """
        if self.live_session:
            self.live_session.stop()
            packets = self.live_session.get_packets()
            self.packets.extend(packets)
            return packets
        return []
    
    def capture_packets(self,
                        interface: str = None,
                        count: int = 100,
                        timeout: int = 30,
                        filter_expr: str = None) -> List[PacketInfo]:
        """
        Capture packets synchronously (blocking).
        
        Args:
            interface: Network interface
            count: Number of packets to capture
            timeout: Timeout in seconds
            filter_expr: BPF filter expression
            
        Returns:
            List of captured PacketInfo objects
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for live capture. Install with: pip install scapy")
        
        captured = []
        
        def callback(pkt):
            try:
                if IP in pkt:
                    packet_info = self._parse_packet(pkt)
                    if packet_info:
                        captured.append(packet_info)
            except Exception:
                pass
        
        try:
            sniff(
                iface=interface,
                prn=callback,
                count=count,
                timeout=timeout,
                filter=filter_expr,
                store=False
            )
        except Exception as e:
            print(f"Capture error: {e}")
        
        self.packets.extend(captured)
        return captured
        
    def read_pcap(self, filepath: str) -> List[PacketInfo]:
        """
        Read packets from a PCAP file.
        
        Args:
            filepath: Path to PCAP file
            
        Returns:
            List of PacketInfo objects
            
        Raises:
            ImportError: If scapy is not installed
            FileNotFoundError: If file doesn't exist
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required to read PCAP files. Install with: pip install scapy")
        
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        
        packets = rdpcap(str(path))
        self.packets = []
        
        for pkt in packets:
            if IP in pkt:
                packet_info = self._parse_packet(pkt)
                if packet_info:
                    self.packets.append(packet_info)
        
        return self.packets
    
    def _parse_packet(self, pkt) -> Optional[PacketInfo]:
        """Parse a scapy packet into PacketInfo."""
        try:
            if IP not in pkt:
                return None
            
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            size = len(pkt)
            timestamp = float(pkt.time) if hasattr(pkt, 'time') else time.time()
            
            # Determine protocol and ports
            if TCP in pkt:
                protocol = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                # Check for TLS (port 443 or TLS handshake)
                tls = dst_port == 443 or src_port == 443
                if Raw in pkt:
                    try:
                        payload = bytes(pkt[Raw].load)
                        # TLS handshake starts with 0x16 (22)
                        if len(payload) > 0 and payload[0] == 0x16:
                            tls = True
                    except:
                        pass
            elif UDP in pkt:
                protocol = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                tls = False
            else:
                return None
            
            return PacketInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=size,
                timestamp=timestamp,
                tls=tls
            )
        except Exception:
            return None
    
    def generate_synthetic_flow(self, 
                                 is_tor: bool = False,
                                 is_bridge: bool = False,
                                 is_vpn: bool = False,
                                 num_packets: int = 100) -> List[PacketInfo]:
        """
        Generate synthetic traffic flow for testing.
        
        Args:
            is_tor: Generate TOR-like traffic
            is_bridge: Generate TOR Bridge traffic
            is_vpn: Generate VPN traffic
            num_packets: Number of packets to generate
            
        Returns:
            List of synthetic PacketInfo objects
        """
        packets = []
        base_time = time.time()
        
        # Select source and destination
        src_ip = f"192.168.1.{random.randint(10, 250)}"
        
        if is_tor:
            dst_ip = random.choice(self.TOR_RELAY_IPS)
            dst_port = random.choice([443, 9001])
            tls = True
        elif is_bridge:
            # Bridges use non-standard IPs but TOR-like patterns
            dst_ip = f"{random.randint(50, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            dst_port = random.choice([443, 8080, 4433])
            tls = True
        elif is_vpn:
            dst_ip = random.choice(self.NORMAL_IPS)
            dst_port = random.choice([1194, 51820, 500])
            tls = False
        else:
            dst_ip = random.choice(self.NORMAL_IPS)
            dst_port = random.choice([80, 443, 8080])
            tls = dst_port == 443
        
        src_port = random.randint(49152, 65535)
        
        for i in range(num_packets):
            if is_tor or is_bridge:
                # TOR uses fixed cell sizes with padding
                base_sizes = [512, 514, 536, 548, 558, 586]
                size = random.choice(base_sizes)
                # Add slight variation
                size += random.randint(-5, 5)
                
                # TOR has consistent IAT (low variance)
                iat = random.gauss(0.05, 0.01)  # Mean 50ms, low variance
            elif is_vpn:
                # VPN has variable sizes but often larger
                size = random.randint(200, 1400)
                iat = random.gauss(0.03, 0.02)
            else:
                # Normal traffic has high variance
                size = random.randint(60, 1500)
                iat = random.expovariate(10)  # Exponential distribution
            
            iat = max(0.001, iat)  # Minimum 1ms
            timestamp = base_time + sum(random.gauss(0.05, 0.02) for _ in range(i))
            
            packets.append(PacketInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol='TCP',
                size=size,
                timestamp=timestamp,
                tls=tls
            ))
        
        self.packets.extend(packets)
        return packets
    
    def generate_mixed_traffic(self, 
                                num_tor_flows: int = 3,
                                num_normal_flows: int = 5,
                                num_bridge_flows: int = 1,
                                num_vpn_flows: int = 1,
                                packets_per_flow: int = 50) -> List[PacketInfo]:
        """
        Generate mixed traffic with various types.
        
        Args:
            num_tor_flows: Number of TOR flows
            num_normal_flows: Number of normal flows
            num_bridge_flows: Number of Bridge flows
            num_vpn_flows: Number of VPN flows
            packets_per_flow: Packets per flow
            
        Returns:
            List of all packets (mixed)
        """
        all_packets = []
        
        # Generate TOR traffic
        for _ in range(num_tor_flows):
            packets = self.generate_synthetic_flow(
                is_tor=True, 
                num_packets=packets_per_flow
            )
            all_packets.extend(packets)
        
        # Generate normal traffic
        for _ in range(num_normal_flows):
            packets = self.generate_synthetic_flow(
                is_tor=False, 
                num_packets=packets_per_flow
            )
            all_packets.extend(packets)
        
        # Generate bridge traffic
        for _ in range(num_bridge_flows):
            packets = self.generate_synthetic_flow(
                is_bridge=True, 
                num_packets=packets_per_flow
            )
            all_packets.extend(packets)
        
        # Generate VPN traffic
        for _ in range(num_vpn_flows):
            packets = self.generate_synthetic_flow(
                is_vpn=True, 
                num_packets=packets_per_flow
            )
            all_packets.extend(packets)
        
        # Sort by timestamp
        all_packets.sort(key=lambda p: p.timestamp)
        
        return all_packets
    
    def stream_packets(self) -> Generator[PacketInfo, None, None]:
        """
        Stream stored packets one at a time.
        
        Yields:
            PacketInfo objects
        """
        for packet in self.packets:
            yield packet
    
    def get_packet_dicts(self) -> List[Dict]:
        """Get all packets as dictionaries."""
        return [p.to_dict() for p in self.packets]
    
    def clear(self):
        """Clear all stored packets."""
        self.packets.clear()
    
    def get_packet_count(self) -> int:
        """Get number of stored packets."""
        return len(self.packets)


def is_scapy_available() -> bool:
    """Check if Scapy is available for live capture."""
    return SCAPY_AVAILABLE

