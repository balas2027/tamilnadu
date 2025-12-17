"""
JA3 Fingerprinter Module.

Phase 2 of Fusion Detection: Extracts and matches TLS fingerprints
for cryptographic identification of TOR clients and relays.

JA3 is a method for creating SSL/TLS client fingerprints that can
be easily produced on any platform and can be used for detecting
known TOR browser connections.
"""

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set

# Known TOR Browser JA3 fingerprints
# These are extracted from TOR Browser (Firefox ESR based)
TOR_JA3_FINGERPRINTS: Set[str] = {
    # TOR Browser 11.x / 12.x (Firefox ESR 91/102)
    '579ccef312d18482fc42e2b822ca2430',  # TOR Browser Windows
    'e7d705a3286e19ea42f587b344ee6865',  # TOR Browser Linux
    'c660d2e99b463d05fb9d7c091b7e3eb2',  # TOR Browser macOS
    'cd08e31494f9531f560d64c695473da9',  # TOR Browser (older)
    
    # Firefox ESR patterns (TOR is based on Firefox)
    '55f8c4ad8f2b1ad5ebbf28e68d9fa0b5',
    'b32309a26951912be7dba376398abc3b',
    
    # Generic TOR patterns
    '3b5074b1b5d032e5620f69f9f700ff0e',
    '5d79227c5bc72dfc64b2f73a7b0c43e5',
}

# Known TOR Relay JA3S fingerprints (Server Hello responses)
TOR_JA3S_FINGERPRINTS: Set[str] = {
    # TOR relay server responses
    'eb1d94daa7e0344597e756a1fb6e7054',
    'ae4edc6faf64d08308082ad26be60767',
    '642a721d8d1d0dcf4b3c7a4c8c9e9fa0',
}


@dataclass
class JA3Result:
    """Result of JA3 fingerprint analysis."""
    ja3_hash: str
    ja3_string: str
    is_tor_client: bool
    confidence: float
    match_type: str  # 'exact', 'partial', 'none'
    
    def to_dict(self) -> Dict:
        return {
            'ja3_hash': self.ja3_hash,
            'ja3_string': self.ja3_string[:50] + '...' if len(self.ja3_string) > 50 else self.ja3_string,
            'is_tor_client': self.is_tor_client,
            'confidence': self.confidence,
            'match_type': self.match_type
        }


class JA3Fingerprinter:
    """
    Extracts and analyzes JA3/JA3S TLS fingerprints.
    
    Provides Phase 2 cryptographic fingerprinting with 85-95% confidence
    for matching TOR Browser connections.
    """
    
    def __init__(self):
        """Initialize JA3 fingerprinter."""
        self._ja3_cache: Dict[str, JA3Result] = {}
        
    def _parse_tls_extensions(self, extensions: bytes) -> List[int]:
        """Parse TLS extensions from raw bytes."""
        ext_list = []
        offset = 0
        
        try:
            while offset < len(extensions) - 4:
                ext_type = int.from_bytes(extensions[offset:offset+2], 'big')
                ext_len = int.from_bytes(extensions[offset+2:offset+4], 'big')
                ext_list.append(ext_type)
                offset += 4 + ext_len
        except:
            pass
        
        return ext_list
    
    def _parse_cipher_suites(self, data: bytes) -> List[int]:
        """Parse cipher suites from TLS data."""
        suites = []
        try:
            for i in range(0, len(data), 2):
                suite = int.from_bytes(data[i:i+2], 'big')
                # Skip GREASE values (0x?a?a pattern)
                if (suite & 0x0f0f) != 0x0a0a:
                    suites.append(suite)
        except:
            pass
        return suites
    
    def extract_ja3_from_packet(self, packet) -> Optional[JA3Result]:
        """
        Extract JA3 fingerprint from a scapy packet.
        
        Args:
            packet: Scapy packet with TLS Client Hello
            
        Returns:
            JA3Result or None if not a Client Hello
        """
        try:
            # Check if packet has Raw layer with TLS data
            from scapy.all import Raw, TCP
            
            if not packet.haslayer(Raw):
                return None
            
            payload = bytes(packet[Raw].load)
            
            # Check for TLS handshake (0x16 = handshake)
            if len(payload) < 6 or payload[0] != 0x16:
                return None
            
            # TLS version from record layer
            tls_version = int.from_bytes(payload[1:3], 'big')
            
            # Check for Client Hello (0x01)
            if payload[5] != 0x01:
                return None
            
            # Parse Client Hello
            return self._parse_client_hello(payload[5:], tls_version)
            
        except Exception as e:
            return None
    
    def _parse_client_hello(self, data: bytes, record_version: int) -> Optional[JA3Result]:
        """Parse TLS Client Hello and generate JA3."""
        try:
            if len(data) < 38:
                return None
            
            # Skip handshake header (4 bytes)
            offset = 4
            
            # Client version (2 bytes)
            client_version = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
            
            # Skip random (32 bytes)
            offset += 32
            
            # Session ID length
            session_id_len = data[offset]
            offset += 1 + session_id_len
            
            # Cipher suites
            cipher_suites_len = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
            cipher_suites = self._parse_cipher_suites(data[offset:offset+cipher_suites_len])
            offset += cipher_suites_len
            
            # Compression methods
            compression_len = data[offset]
            offset += 1 + compression_len
            
            # Extensions
            extensions = []
            elliptic_curves = []
            ec_point_formats = []
            
            if offset < len(data) - 2:
                extensions_len = int.from_bytes(data[offset:offset+2], 'big')
                offset += 2
                ext_data = data[offset:offset+extensions_len]
                
                # Parse extensions
                ext_offset = 0
                while ext_offset < len(ext_data) - 4:
                    ext_type = int.from_bytes(ext_data[ext_offset:ext_offset+2], 'big')
                    ext_len = int.from_bytes(ext_data[ext_offset+2:ext_offset+4], 'big')
                    
                    # Skip GREASE
                    if (ext_type & 0x0f0f) != 0x0a0a:
                        extensions.append(ext_type)
                    
                    # Elliptic curves (extension type 10)
                    if ext_type == 10 and ext_len >= 2:
                        curves_len = int.from_bytes(ext_data[ext_offset+4:ext_offset+6], 'big')
                        for i in range(0, curves_len, 2):
                            curve = int.from_bytes(ext_data[ext_offset+6+i:ext_offset+8+i], 'big')
                            if (curve & 0x0f0f) != 0x0a0a:
                                elliptic_curves.append(curve)
                    
                    # EC point formats (extension type 11)
                    if ext_type == 11 and ext_len >= 1:
                        formats_len = ext_data[ext_offset+4]
                        ec_point_formats = list(ext_data[ext_offset+5:ext_offset+5+formats_len])
                    
                    ext_offset += 4 + ext_len
            
            # Build JA3 string
            # Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            ja3_string = ','.join([
                str(client_version),
                '-'.join(str(c) for c in cipher_suites),
                '-'.join(str(e) for e in extensions),
                '-'.join(str(c) for c in elliptic_curves),
                '-'.join(str(f) for f in ec_point_formats)
            ])
            
            # Calculate MD5 hash
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
            
            # Check if it matches known TOR fingerprints
            if ja3_hash in TOR_JA3_FINGERPRINTS:
                return JA3Result(
                    ja3_hash=ja3_hash,
                    ja3_string=ja3_string,
                    is_tor_client=True,
                    confidence=0.95,
                    match_type='exact'
                )
            
            # Check for partial match (similar cipher suites)
            tor_like_score = self._calculate_tor_similarity(cipher_suites, extensions)
            if tor_like_score > 0.7:
                return JA3Result(
                    ja3_hash=ja3_hash,
                    ja3_string=ja3_string,
                    is_tor_client=True,
                    confidence=0.75 + (tor_like_score - 0.7) * 0.5,
                    match_type='partial'
                )
            
            return JA3Result(
                ja3_hash=ja3_hash,
                ja3_string=ja3_string,
                is_tor_client=False,
                confidence=0.0,
                match_type='none'
            )
            
        except Exception as e:
            return None
    
    def _calculate_tor_similarity(self, cipher_suites: List[int], extensions: List[int]) -> float:
        """
        Calculate similarity to known TOR Browser patterns.
        
        Returns a score between 0 and 1.
        """
        score = 0.0
        
        # TOR Browser typically uses these cipher suites (TLS 1.3 focused)
        tor_ciphers = {
            0x1301,  # TLS_AES_128_GCM_SHA256
            0x1302,  # TLS_AES_256_GCM_SHA384
            0x1303,  # TLS_CHACHA20_POLY1305_SHA256
            0xc02b,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc02c,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        }
        
        # Check cipher overlap
        cipher_overlap = len(set(cipher_suites) & tor_ciphers)
        if cipher_overlap >= 4:
            score += 0.4
        elif cipher_overlap >= 2:
            score += 0.2
        
        # TOR typically has these extensions
        tor_extensions = {0, 5, 10, 11, 13, 16, 23, 35, 43, 45, 51, 65281}
        ext_overlap = len(set(extensions) & tor_extensions)
        if ext_overlap >= 8:
            score += 0.4
        elif ext_overlap >= 5:
            score += 0.2
        
        # TOR typically has limited cipher suites (not too many)
        if 10 <= len(cipher_suites) <= 20:
            score += 0.2
        
        return min(score, 1.0)
    
    def analyze_flow_fingerprint(self, packets: List) -> Tuple[float, str, Optional[JA3Result]]:
        """
        Analyze a flow for TOR fingerprint patterns.
        
        Args:
            packets: List of packets in the flow
            
        Returns:
            (confidence, reason, ja3_result) tuple
        """
        for pkt in packets[:10]:  # Check first 10 packets for Client Hello
            result = self.extract_ja3_from_packet(pkt)
            if result:
                if result.match_type == 'exact':
                    return result.confidence, f"Exact JA3 match: {result.ja3_hash[:16]}...", result
                elif result.match_type == 'partial':
                    return result.confidence, f"Partial JA3 match (TOR-like): {result.ja3_hash[:16]}...", result
        
        return 0.0, "No TLS fingerprint detected", None
    
    def get_fingerprint_confidence(self, 
                                   ja3_hash: Optional[str] = None,
                                   tls_detected: bool = False,
                                   port: int = 0) -> Tuple[float, str]:
        """
        Calculate Phase 2 fingerprint confidence.
        
        Args:
            ja3_hash: JA3 hash if available
            tls_detected: Whether TLS was detected
            port: Destination port
            
        Returns:
            (confidence, reason) tuple
        """
        if ja3_hash and ja3_hash in TOR_JA3_FINGERPRINTS:
            return 0.95, f"Exact TOR JA3 fingerprint match"
        
        if tls_detected:
            if port in [9001, 9030]:
                return 0.75, "TLS on TOR ORPort"
            elif port == 443:
                return 0.40, "TLS on standard HTTPS (needs pattern confirmation)"
            else:
                return 0.30, "TLS on non-standard port"
        
        return 0.0, "No TLS/fingerprint indicators"


# Simplified fingerprinting for when we don't have raw packets
class SimplifiedFingerprinter:
    """
    Simplified fingerprinting based on flow-level TLS indicators.
    
    Used when raw packet data is not available.
    """
    
    def get_fingerprint_score(self, 
                              tls_detected: bool,
                              port: int,
                              packet_sizes: List[int] = None) -> Tuple[float, str]:
        """
        Calculate fingerprint score from flow indicators.
        
        Args:
            tls_detected: Whether TLS was detected
            port: Destination port
            packet_sizes: List of packet sizes in flow
            
        Returns:
            (confidence, reason) tuple
        """
        score = 0.0
        reasons = []
        
        if tls_detected:
            score += 0.30
            reasons.append("TLS encrypted")
            
            if port == 9001:
                score += 0.40
                reasons.append("TOR ORPort 9001")
            elif port == 9030:
                score += 0.35
                reasons.append("TOR DirPort 9030")
            elif port == 443:
                score += 0.10
                reasons.append("HTTPS port 443")
            
            # Check for TOR-like initial handshake sizes
            if packet_sizes and len(packet_sizes) >= 3:
                # TOR Client Hello is typically around 500-600 bytes
                first_size = packet_sizes[0]
                if 450 <= first_size <= 650:
                    score += 0.15
                    reasons.append(f"TOR-like Client Hello ({first_size}B)")
        
        return min(score, 1.0), " + ".join(reasons) if reasons else "No fingerprint indicators"
