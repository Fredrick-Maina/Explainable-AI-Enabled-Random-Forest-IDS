import threading
import time
from src.hids.file_integrity import FileIntegrityMonitor
from src.hids.log_monitor import LogMonitor
from src.core.logger import system_logger

class HIDSManager:
    """
    Orchestrates Host-based IDS components.
    """
    def __init__(self, watch_list=None, log_file="/var/log/auth.log"):
        self.fim = FileIntegrityMonitor(watch_list=watch_list)
        self.log_monitor = LogMonitor(log_file=log_file)
        self.fim_thread = None
        self.is_running = False

    def start(self):
        system_logger.info("Initializing HIDS Components...")
        self.is_running = True
        
        # Start Log Monitor (it handles its own threading)
        self.log_monitor.start()
        
        # Start FIM in a periodic loop thread
        self.fim_thread = threading.Thread(target=self._fim_loop, daemon=True)
        self.fim_thread.start()

    def _fim_loop(self):
        """Periodically run integrity checks (e.g., every 10 minutes)."""
        while self.is_running:
            self.fim.check_integrity()
            # Sleep for 600 seconds (10 minutes)
            # Shortened to 60s for prototype/testing purposes
            time.sleep(60)

    def stop(self):
        self.is_running = False
        self.log_monitor.stop()
        system_logger.info("HIDS Manager stopped.")

if __name__ == "__main__":
    manager = HIDSManager()
    manager.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        manager.stop()
