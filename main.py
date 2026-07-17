import threading
import sys
import time
import signal
import platform
from src.core.logger import system_logger
from src.nids.sniffer import NIDSSniffer
from src.nids.flow_manager import FlowManager
from src.ml.engine import MLEngine
from src.hids.manager import HIDSManager

class HybridIDS:
    def __init__(self, interface=None, log_file=None, pcap_file=None):
        self.os_type = platform.system()
        self.pcap_file = pcap_file
        
        # 1. Platform-aware Interface selection
        if interface:
            self.interface = interface
        elif pcap_file:
            self.interface = None # Not needed for PCAP replay
        else:
            # Default to None to let Scapy decide, or set OS-specific fallback
            self.interface = "eth0" if self.os_type == "Linux" else None

        # 2. Platform-aware Log file selection
        if log_file:
            self.log_file = log_file
        else:
            if self.os_type == "Linux":
                self.log_file = "/var/log/auth.log"
            elif self.os_type == "Windows":
                # Windows doesn't use simple log files for auth, but we can provide a dummy or temp path
                self.log_file = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
            else:
                self.log_file = "/var/log/system.log"

        self.running = True
        
        # Initialize Components
        system_logger.info(f"Initializing Hybrid IDS on {self.os_type}...")
        self.ml_engine = MLEngine()
        self.flow_manager = FlowManager()
        self.hids_manager = HIDSManager(log_file=self.log_file)
        self.nids_sniffer = NIDSSniffer(interface=self.interface, pcap_file=self.pcap_file)

    def start(self):
        print(f"""
    ========================================
       Hybrid AI-Intrusion Detection System
    ========================================
     [OS]: {self.os_type}
     [Interface]: {self.interface or 'Auto-detect'}
     [Log File]: {self.log_file}
    ========================================
        """)
        
        # 1. Start HIDS (Internal threading)
        self.hids_manager.start()
        
        # 2. Start NIDS (Blocking operation)
        system_logger.info("IDS is now active and monitoring.")
        try:
            self.nids_sniffer.start()
        except Exception as e:
            system_logger.critical(f"Fatal error in NIDS sniffer: {e}")
            self.stop()

    def stop(self, signum=None, frame=None):
        print("\n[*] Shutting down Hybrid IDS...")
        self.running = False
        self.hids_manager.stop()
        system_logger.info("User initiated shutdown.")
        sys.exit(0)

def main():
    interface = "eth0"
    if len(sys.argv) > 1:
        interface = sys.argv[1]

    ids = HybridIDS(interface=interface)
    
    # Handle signals for graceful shutdown
    signal.signal(signal.SIGINT, ids.stop)
    signal.signal(signal.SIGTERM, ids.stop)
    
    ids.start()

if __name__ == "__main__":
    main()
rgs.log, pcap_file=args.pcap)
    
    # Handle signals for graceful shutdown
    signal.signal(signal.SIGINT, ids.stop)
    signal.signal(signal.SIGTERM, ids.stop)
    
    ids.start()

if __name__ == "__main__":
    main()
