"""
TOR Hidden Service Manager.

This module helps set up and manage the TOR Traffic Analyzer
as a Hidden Service (Onion Service) on the TOR network.

Features:
- Programmatic hidden service creation via stem
- Automatic .onion address generation
- Service monitoring and status
"""

import os
import time
from pathlib import Path
from typing import Optional, Tuple, Dict

# Try to import stem
try:
    from stem.control import Controller
    from stem import Signal
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False
    Controller = None


class HiddenServiceManager:
    """
    Manages TOR Hidden Service for the analyzer.
    
    This allows the TOR Traffic Analyzer to be hosted as
    a .onion hidden service, accessible only via TOR.
    """
    
    DEFAULT_CONTROL_PORT = 9051
    DEFAULT_LOCAL_PORT = 8501  # Streamlit default
    
    def __init__(self, 
                 control_port: int = 9051,
                 control_password: Optional[str] = None,
                 service_dir: Optional[str] = None):
        """
        Initialize Hidden Service Manager.
        
        Args:
            control_port: TOR control port (default 9051)
            control_password: Password for control port auth
            service_dir: Directory to store hidden service keys
        """
        self.control_port = control_port
        self.control_password = control_password
        self.service_dir = Path(service_dir) if service_dir else Path(__file__).parent.parent / 'hidden_service'
        
        self._controller: Optional[Controller] = None
        self._connected = False
        self._onion_address: Optional[str] = None
        self._service_id: Optional[str] = None
        
    def connect(self) -> bool:
        """
        Connect to TOR control port.
        
        Returns:
            True if connected successfully
        """
        if not STEM_AVAILABLE:
            print("❌ Stem library not available. Install with: pip install stem")
            return False
        
        try:
            self._controller = Controller.from_port(port=self.control_port)
            
            if self.control_password:
                self._controller.authenticate(password=self.control_password)
            else:
                self._controller.authenticate()
            
            self._connected = True
            print(f"✅ Connected to TOR @ 127.0.0.1:{self.control_port}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to connect to TOR: {e}")
            print("   Make sure TOR is running and ControlPort 9051 is enabled in torrc")
            return False
    
    def create_hidden_service(self, 
                              local_port: int = 8501,
                              virtual_port: int = 80) -> Optional[str]:
        """
        Create a hidden service for the Streamlit app.
        
        This programmatically creates a hidden service that
        forwards traffic from the .onion address to the local
        Streamlit server.
        
        Args:
            local_port: Local port where Streamlit runs (default 8501)
            virtual_port: External port on .onion address (default 80)
            
        Returns:
            The .onion address, or None if failed
        """
        if not self._connected:
            if not self.connect():
                return None
        
        try:
            # Create hidden service
            response = self._controller.create_ephemeral_hidden_service(
                ports={virtual_port: f"127.0.0.1:{local_port}"},
                await_publication=True,
                detached=True
            )
            
            self._service_id = response.service_id
            self._onion_address = f"{response.service_id}.onion"
            
            print(f"\n🧅 Hidden Service Created!")
            print(f"   Address: http://{self._onion_address}")
            print(f"   Mapping: Port {virtual_port} → 127.0.0.1:{local_port}")
            print(f"\n   Access via TOR Browser at: http://{self._onion_address}")
            
            # Save the address to a file
            hostname_file = self.service_dir / 'hostname'
            self.service_dir.mkdir(parents=True, exist_ok=True)
            with open(hostname_file, 'w') as f:
                f.write(self._onion_address)
            print(f"   Address saved to: {hostname_file}")
            
            return self._onion_address
            
        except Exception as e:
            print(f"❌ Failed to create hidden service: {e}")
            return None
    
    def create_persistent_hidden_service(self,
                                         local_port: int = 8501,
                                         virtual_port: int = 80) -> Optional[str]:
        """
        Create a persistent hidden service with saved keys.
        
        Unlike ephemeral services, this service persists across
        TOR restarts and maintains the same .onion address.
        
        Note: This requires the HiddenServiceDir to be configured
        in torrc. Use the torrc.example file as a template.
        
        Args:
            local_port: Local port where Streamlit runs
            virtual_port: External port on .onion address
            
        Returns:
            The .onion address, or None if failed
        """
        # Check if hostname file already exists
        hostname_file = self.service_dir / 'hostname'
        
        if hostname_file.exists():
            with open(hostname_file, 'r') as f:
                self._onion_address = f.read().strip()
            print(f"🧅 Existing Hidden Service Found!")
            print(f"   Address: http://{self._onion_address}")
            return self._onion_address
        
        print("ℹ️  No existing hidden service found.")
        print("   To create a persistent service, add these lines to your torrc:")
        print(f"   HiddenServiceDir {self.service_dir}")
        print(f"   HiddenServicePort {virtual_port} 127.0.0.1:{local_port}")
        print("   Then restart TOR.")
        
        return None
    
    def remove_hidden_service(self) -> bool:
        """
        Remove the ephemeral hidden service.
        
        Returns:
            True if removed successfully
        """
        if not self._connected or not self._service_id:
            return False
        
        try:
            self._controller.remove_ephemeral_hidden_service(self._service_id)
            print(f"✅ Hidden service {self._onion_address} removed")
            self._onion_address = None
            self._service_id = None
            return True
        except Exception as e:
            print(f"❌ Failed to remove hidden service: {e}")
            return False
    
    def get_onion_address(self) -> Optional[str]:
        """Get the current .onion address."""
        return self._onion_address
    
    def is_running(self) -> bool:
        """Check if hidden service is running."""
        return self._onion_address is not None and self._connected
    
    def get_status(self) -> Dict:
        """Get hidden service status."""
        return {
            'connected_to_tor': self._connected,
            'onion_address': self._onion_address,
            'service_id': self._service_id,
            'stem_available': STEM_AVAILABLE
        }
    
    def close(self):
        """Close connection and cleanup."""
        if self._service_id and self._controller:
            try:
                self._controller.remove_ephemeral_hidden_service(self._service_id)
            except:
                pass
        
        if self._controller:
            self._controller.close()
        
        self._connected = False


def start_as_hidden_service(local_port: int = 8501) -> Optional[str]:
    """
    Quick helper to start the analyzer as a hidden service.
    
    Args:
        local_port: Port where Streamlit is running
        
    Returns:
        .onion address or None
    """
    manager = HiddenServiceManager()
    return manager.create_hidden_service(local_port=local_port)


if __name__ == "__main__":
    print("=" * 60)
    print("  TOR Traffic Analyzer - Hidden Service Setup")
    print("=" * 60)
    print()
    
    manager = HiddenServiceManager()
    
    # Try to create ephemeral hidden service
    onion_address = manager.create_hidden_service()
    
    if onion_address:
        print("\n" + "=" * 60)
        print("  ✅ SUCCESS! Your analyzer is now a Hidden Service")
        print("=" * 60)
        print(f"\n  Access URL: http://{onion_address}")
        print("  (Open this in TOR Browser)")
        print("\n  Press Ctrl+C to stop the hidden service")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n  Shutting down hidden service...")
            manager.close()
            print("  ✅ Hidden service stopped")
    else:
        print("\n  ❌ Failed to create hidden service")
        print("  Make sure TOR is running with ControlPort enabled")
