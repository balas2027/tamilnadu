"""
TOR Hidden Service Manager - Forensic Simulation Edition.

Updated for TN Police Hackathon 2025:
- Remote connection support (IP: 10.0.6.18)
- External cookie authentication
- Automatic .onion generation for remote target testing
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
    Configured to allow remote monitoring from the Forensic Server.
    """
    
    # Updated for your specific network configuration
    DEFAULT_CONTROL_ADDR = "10.0.6.18" 
    DEFAULT_CONTROL_PORT = 9051
    DEFAULT_LOCAL_PORT = 8501  # Streamlit default
    
    def __init__(self, 
                 control_addr: str = "10.0.6.18",
                 control_port: int = 9051,
                 control_password: Optional[str] = None,
                 service_dir: Optional[str] = None):
        """
        Initialize Hidden Service Manager for Remote Forensic Analysis.
        """
        self.control_addr = control_addr
        self.control_port = control_port
        self.control_password = control_password
        # Path to store the generated .onion keys
        self.service_dir = Path(service_dir) if service_dir else Path(__file__).parent / 'hidden_service'
        
        self._controller: Optional[Controller] = None
        self._connected = False
        self._onion_address: Optional[str] = None
        self._service_id = None
        
    def connect(self) -> bool:
        """
        Connect to TOR control port using the Forensic Server IP.
        """
        if not STEM_AVAILABLE:
            print("❌ Stem library not available. Install with: pip install stem")
            return False
        
        try:
            # Connect to your Laptop's IP instead of localhost
            self._controller = Controller.from_port(address=self.control_addr, port=self.control_port)
            
            # Authentication logic for remote session
            # Ensure 'control_auth_cookie' is present in the current directory
            cookie_path = os.path.join(os.getcwd(), 'control_auth_cookie')
            
            if os.path.exists(cookie_path):
                 self._controller.authenticate(cookie_path=cookie_path)
                 print(f"✅ Authenticated using local cookie: {cookie_path}")
            elif self.control_password:
                self._controller.authenticate(password=self.control_password)
            else:
                self._controller.authenticate()
            
            self._connected = True
            print(f"✅ Connected to Forensic TOR Server @ {self.control_addr}:{self.control_port}")
            return True
            
        except Exception as e:
            print(f"❌ Connection Failed: {e}")
            print(f"💡 Check: torrc has 'ControlPort 0.0.0.0:9051' and Firewall allows Port 9051.")
            return False
    
    def create_hidden_service(self, 
                              local_port: int = 8501,
                              virtual_port: int = 80) -> Optional[str]:
        """
        Creates the .onion gateway for the demo.
        """
        if not self._connected:
            if not self.connect():
                return None
        
        try:
            # Create the ephemeral .onion link
            response = self._controller.create_ephemeral_hidden_service(
                ports={virtual_port: f"127.0.0.1:{local_port}"},
                await_publication=True,
                detached=True
            )
            
            self._service_id = response.service_id
            self._onion_address = f"{response.service_id}.onion"
            
            # Save the forensic hostname for the report
            self.service_dir.mkdir(parents=True, exist_ok=True)
            with open(self.service_dir / 'hostname', 'w') as f:
                f.write(self._onion_address)
            
            return self._onion_address
            
        except Exception as e:
            print(f"❌ Failed to create hidden service: {e}")
            return None

    def close(self):
        """Cleanup for demo termination."""
        if self._service_id and self._controller:
            try:
                self._controller.remove_ephemeral_hidden_service(self._service_id)
            except: pass
        if self._controller:
            self._controller.close()
        self._connected = False


if __name__ == "__main__":
    print("=" * 60)
    print("   TN POLICE HACKATHON 2025 - TOR FORENSIC SIMULATOR")
    print("=" * 60)
    
    manager = HiddenServiceManager()
    onion = manager.create_hidden_service()
    
    if onion:
        print(f"\n✅ Forensic Gateway Active: http://{onion}")
        print(f"📋 Step: Copy this URL to the Target Laptop (Friend).")
        print("\n--- Monitoring Circuits (Press Ctrl+C to Stop) ---")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            manager.close()
            print("\n✅ Simulation Stopped.")
    else:
        print("\n❌ Setup Failed. Ensure TOR is running on 10.0.6.18:9051")