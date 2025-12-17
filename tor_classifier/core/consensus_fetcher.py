"""
TOR Consensus Fetcher Module.

Phase 1 of Fusion Detection: Fetches live TOR relay directory
and provides definitive identity matching for TOR relays.

This module can fetch data from:
1. Local TOR instance via stem library (PREFERRED - direct connection)
2. TOR Directory Authorities via stem
3. TOR Project's Onionoo API (fallback)
4. Cached consensus data
"""

import time
import hashlib
import requests
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import json

# Try to import stem for direct TOR consensus access
try:
    from stem.descriptor.remote import DescriptorDownloader
    from stem.descriptor.networkstatus import NetworkStatusDocumentV3
    from stem.control import Controller
    from stem import Signal
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False
    Controller = None


@dataclass
class RelayInfo:
    """Information about a TOR relay."""
    fingerprint: str
    nickname: str
    address: str
    or_port: int
    dir_port: int
    flags: List[str]
    bandwidth: int
    is_guard: bool
    is_exit: bool
    
    def to_dict(self) -> Dict:
        return {
            'fingerprint': self.fingerprint,
            'nickname': self.nickname,
            'address': self.address,
            'or_port': self.or_port,
            'dir_port': self.dir_port,
            'flags': self.flags,
            'bandwidth': self.bandwidth,
            'is_guard': self.is_guard,
            'is_exit': self.is_exit
        }


class ConsensusFetcher:
    """
    Fetches and caches TOR network consensus data.
    
    Provides Phase 1 identity matching with 95-100% confidence
    for known TOR relays.
    """
    
    # TOR Project's CollecTor API
    COLLECTOR_URL = "https://onionoo.torproject.org/details"
    
    # Cache duration (1 hour)
    CACHE_DURATION = 3600
    
    # Default TOR control port settings
    DEFAULT_CONTROL_PORT = 9051
    DEFAULT_CONTROL_HOST = "127.0.0.1"
    
    def __init__(self, cache_dir: Optional[str] = None, 
                 control_port: int = 9051,
                 control_password: Optional[str] = None):
        """
        Initialize consensus fetcher.
        
        Args:
            cache_dir: Directory to store cached consensus data
            control_port: TOR control port (default 9051)
            control_password: Password for control port authentication (optional)
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / '.tor_classifier_cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.control_port = control_port
        self.control_password = control_password
        self._controller: Optional[Controller] = None
        self._connected_to_tor = False
        
        self._relays: Dict[str, RelayInfo] = {}  # IP -> RelayInfo
        self._relay_ips: Set[str] = set()
        self._guard_ips: Set[str] = set()
        self._exit_ips: Set[str] = set()
        self._entry_guards: Set[str] = set()  # Current client's entry guards
        self._last_fetch: float = 0
        self._is_loaded = False
        self._fetch_source = "none"
        
    def _get_cache_path(self) -> Path:
        """Get path to cache file."""
        return self.cache_dir / 'tor_consensus.json'
    
    def _load_from_cache(self) -> bool:
        """Load consensus from cache if valid."""
        cache_path = self._get_cache_path()
        
        if not cache_path.exists():
            return False
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
            
            # Check if cache is still valid
            cache_time = data.get('timestamp', 0)
            if time.time() - cache_time > self.CACHE_DURATION:
                return False
            
            # Load relay data
            for relay_data in data.get('relays', []):
                relay = RelayInfo(**relay_data)
                self._relays[relay.address] = relay
                self._relay_ips.add(relay.address)
                if relay.is_guard:
                    self._guard_ips.add(relay.address)
                if relay.is_exit:
                    self._exit_ips.add(relay.address)
            
            self._last_fetch = cache_time
            self._is_loaded = True
            return True
            
        except Exception as e:
            print(f"Cache load error: {e}")
            return False
    
    def _save_to_cache(self):
        """Save consensus to cache."""
        cache_path = self._get_cache_path()
        
        try:
            data = {
                'timestamp': time.time(),
                'relays': [r.to_dict() for r in self._relays.values()]
            }
            with open(cache_path, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            print(f"Cache save error: {e}")
    
    def fetch_from_onionoo(self) -> bool:
        """
        Fetch relay data from TOR Project's Onionoo API.
        
        Returns:
            True if successful
        """
        try:
            # Fetch guards and relays
            params = {
                'type': 'relay',
                'running': 'true',
                'fields': 'fingerprint,nickname,or_addresses,dir_address,flags,bandwidth'
            }
            
            response = requests.get(
                self.COLLECTOR_URL,
                params=params,
                timeout=30,
                headers={'User-Agent': 'TOR-Traffic-Analyzer/1.0'}
            )
            response.raise_for_status()
            data = response.json()
            
            self._relays.clear()
            self._relay_ips.clear()
            self._guard_ips.clear()
            self._exit_ips.clear()
            
            for relay in data.get('relays', []):
                # Parse OR addresses
                or_addresses = relay.get('or_addresses', [])
                if not or_addresses:
                    continue
                
                # Get primary address (first one, usually IPv4)
                primary_addr = or_addresses[0]
                if ':' in primary_addr:
                    # Handle IPv4:port format
                    parts = primary_addr.rsplit(':', 1)
                    ip = parts[0].strip('[]')
                    port = int(parts[1]) if len(parts) > 1 else 9001
                else:
                    ip = primary_addr
                    port = 9001
                
                flags = relay.get('flags', [])
                
                relay_info = RelayInfo(
                    fingerprint=relay.get('fingerprint', ''),
                    nickname=relay.get('nickname', 'Unknown'),
                    address=ip,
                    or_port=port,
                    dir_port=relay.get('dir_address', 0),
                    flags=flags,
                    bandwidth=relay.get('bandwidth', [0, 0, 0])[0] if relay.get('bandwidth') else 0,
                    is_guard='Guard' in flags,
                    is_exit='Exit' in flags
                )
                
                self._relays[ip] = relay_info
                self._relay_ips.add(ip)
                
                if relay_info.is_guard:
                    self._guard_ips.add(ip)
                if relay_info.is_exit:
                    self._exit_ips.add(ip)
            
            self._last_fetch = time.time()
            self._is_loaded = True
            self._save_to_cache()
            
            return True
            
        except Exception as e:
            print(f"Onionoo fetch error: {e}")
            return False
    
    def connect_to_local_tor(self) -> bool:
        """
        Connect to local TOR daemon via control port.
        
        This enables real-time monitoring of TOR circuits and
        access to the client's actual entry guards.
        
        Returns:
            True if connection successful
        """
        if not STEM_AVAILABLE or Controller is None:
            print("Stem library not available")
            return False
        
        try:
            # Connect to TOR control port
            self._controller = Controller.from_port(
                address=self.DEFAULT_CONTROL_HOST,
                port=self.control_port
            )
            
            # Authenticate (tries cookie auth first, then password)
            if self.control_password:
                self._controller.authenticate(password=self.control_password)
            else:
                self._controller.authenticate()
            
            self._connected_to_tor = True
            print(f"Connected to TOR @ {self.DEFAULT_CONTROL_HOST}:{self.control_port}")
            return True
            
        except Exception as e:
            print(f"Failed to connect to TOR control port: {e}")
            self._connected_to_tor = False
            return False
    
    def fetch_from_local_tor(self) -> bool:
        """
        Fetch consensus directly from local TOR daemon.
        
        This is the most accurate method as it uses the same
        data that TOR itself uses for routing.
        
        Returns:
            True if successful
        """
        if not self._connected_to_tor:
            if not self.connect_to_local_tor():
                return False
        
        try:
            # Get network status from local TOR
            self._relays.clear()
            self._relay_ips.clear()
            self._guard_ips.clear()
            self._exit_ips.clear()
            
            # Get consensus via controller
            for status in self._controller.get_network_statuses():
                flags = list(status.flags) if status.flags else []
                
                relay_info = RelayInfo(
                    fingerprint=status.fingerprint,
                    nickname=status.nickname,
                    address=status.address,
                    or_port=status.or_port,
                    dir_port=status.dir_port or 0,
                    flags=flags,
                    bandwidth=status.bandwidth or 0,
                    is_guard='Guard' in flags,
                    is_exit='Exit' in flags
                )
                
                self._relays[status.address] = relay_info
                self._relay_ips.add(status.address)
                
                if relay_info.is_guard:
                    self._guard_ips.add(status.address)
                if relay_info.is_exit:
                    self._exit_ips.add(status.address)
            
            # Also get client's actual entry guards
            try:
                entry_guards_response = self._controller.get_info('entry-guards')
                if entry_guards_response:
                    for line in entry_guards_response.split('\n'):
                        if line.strip():
                            # Parse guard fingerprint
                            parts = line.split()
                            if len(parts) >= 1:
                                fingerprint = parts[0].replace('$', '').split('~')[0]
                                # Find the IP for this guard
                                for ip, relay in self._relays.items():
                                    if relay.fingerprint == fingerprint:
                                        self._entry_guards.add(ip)
                                        break
            except:
                pass  # entry-guards may not be available
            
            self._last_fetch = time.time()
            self._is_loaded = True
            self._fetch_source = "local_tor"
            self._save_to_cache()
            
            print(f"Loaded {len(self._relay_ips)} relays from local TOR")
            return True
            
        except Exception as e:
            print(f"Local TOR fetch error: {e}")
            return False
    
    def get_current_circuits(self) -> List[Dict]:
        """
        Get current TOR circuits from local daemon.
        
        Returns:
            List of circuit information
        """
        if not self._connected_to_tor or not self._controller:
            return []
        
        circuits = []
        try:
            for circ in self._controller.get_circuits():
                circuit_info = {
                    'id': circ.id,
                    'status': circ.status,
                    'purpose': circ.purpose,
                    'path': [(entry.fingerprint, entry.nickname) for entry in circ.path],
                    'created': str(circ.created) if circ.created else None
                }
                circuits.append(circuit_info)
        except Exception as e:
            print(f"Error getting circuits: {e}")
        
        return circuits
    
    def is_my_entry_guard(self, ip: str) -> bool:
        """Check if IP is one of the client's current entry guards."""
        return ip in self._entry_guards
    
    def fetch_from_stem(self) -> bool:
        """
        Fetch consensus via stem library (from directory authorities).
        
        Returns:
            True if successful
        """
        if not STEM_AVAILABLE:
            return False
        
        try:
            downloader = DescriptorDownloader()
            consensus = downloader.get_consensus().run()
            
            self._relays.clear()
            self._relay_ips.clear()
            self._guard_ips.clear()
            self._exit_ips.clear()
            
            for router in consensus:
                flags = list(router.flags) if router.flags else []
                
                relay_info = RelayInfo(
                    fingerprint=router.fingerprint,
                    nickname=router.nickname,
                    address=router.address,
                    or_port=router.or_port,
                    dir_port=router.dir_port or 0,
                    flags=flags,
                    bandwidth=router.bandwidth or 0,
                    is_guard='Guard' in flags,
                    is_exit='Exit' in flags
                )
                
                self._relays[router.address] = relay_info
                self._relay_ips.add(router.address)
                
                if relay_info.is_guard:
                    self._guard_ips.add(router.address)
                if relay_info.is_exit:
                    self._exit_ips.add(router.address)
            
            self._last_fetch = time.time()
            self._is_loaded = True
            self._fetch_source = "stem_directory"
            self._save_to_cache()
            
            return True
            
        except Exception as e:
            print(f"Stem fetch error: {e}")
            return False
    
    def fetch_consensus(self, force: bool = False) -> bool:
        """
        Fetch TOR consensus data.
        
        Tries in order (most accurate first):
        1. Load from cache (if valid)
        2. Connect to local TOR daemon (BEST - uses same data as TOR)
        3. Fetch from directory authorities via stem
        4. Fetch from Onionoo API (fallback)
        
        Args:
            force: Force refresh, ignore cache
            
        Returns:
            True if data was loaded successfully
        """
        # Check cache first
        if not force and self._is_loaded:
            if time.time() - self._last_fetch < self.CACHE_DURATION:
                return True
        
        if not force and self._load_from_cache():
            self._fetch_source = "cache"
            return True
        
        # Try local TOR first (BEST - direct connection to running TOR)
        if STEM_AVAILABLE and self.fetch_from_local_tor():
            return True
        
        # Try stem directory authorities
        if STEM_AVAILABLE and self.fetch_from_stem():
            return True
        
        # Fall back to Onionoo API
        if self.fetch_from_onionoo():
            self._fetch_source = "onionoo_api"
            return True
        
        return False
    
    def is_known_relay(self, ip: str) -> bool:
        """
        Check if IP is a known TOR relay.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is in current consensus
        """
        if not self._is_loaded:
            self.fetch_consensus()
        return ip in self._relay_ips
    
    def is_guard(self, ip: str) -> bool:
        """Check if IP is a Guard relay."""
        if not self._is_loaded:
            self.fetch_consensus()
        return ip in self._guard_ips
    
    def is_exit(self, ip: str) -> bool:
        """Check if IP is an Exit relay."""
        if not self._is_loaded:
            self.fetch_consensus()
        return ip in self._exit_ips
    
    def get_relay_info(self, ip: str) -> Optional[RelayInfo]:
        """
        Get detailed information about a relay.
        
        Args:
            ip: IP address of relay
            
        Returns:
            RelayInfo or None if not found
        """
        if not self._is_loaded:
            self.fetch_consensus()
        return self._relays.get(ip)
    
    def get_identity_confidence(self, ip: str, port: int) -> Tuple[float, str]:
        """
        Calculate Phase 1 identity confidence score.
        
        Args:
            ip: Destination IP
            port: Destination port
            
        Returns:
            (confidence, reason) tuple
        """
        if not self._is_loaded:
            self.fetch_consensus()
        
        relay = self._relays.get(ip)
        
        if relay:
            # Known relay in consensus
            if port == relay.or_port:
                # Exact port match
                if relay.is_guard:
                    return 1.0, f"Consensus Guard relay: {relay.nickname}"
                return 0.98, f"Consensus relay: {relay.nickname}"
            elif port in [9001, 9030, 443]:
                # TOR port but different from listed
                return 0.95, f"Consensus relay on TOR port: {relay.nickname}"
            elif port == 80:
                # HTTP - possible false positive
                return 0.60, f"Consensus relay on HTTP (suspicious): {relay.nickname}"
            else:
                return 0.85, f"Consensus relay, non-standard port: {relay.nickname}"
        
        # Not in consensus - check port-based heuristics
        if port == 9001:
            return 0.70, "TOR ORPort 9001 (not in current consensus)"
        elif port == 9030:
            return 0.65, "TOR DirPort 9030 (not in current consensus)"
        
        return 0.0, "Not a known TOR relay"
    
    def get_stats(self) -> Dict:
        """Get statistics about loaded consensus."""
        return {
            'total_relays': len(self._relay_ips),
            'guards': len(self._guard_ips),
            'exits': len(self._exit_ips),
            'my_entry_guards': len(self._entry_guards),
            'last_fetch': self._last_fetch,
            'cache_valid': time.time() - self._last_fetch < self.CACHE_DURATION if self._last_fetch else False,
            'source': self._fetch_source,
            'connected_to_tor': self._connected_to_tor,
            'stem_available': STEM_AVAILABLE
        }
