import re
import time
import os
import threading
import platform
from src.core.event_bus import bus
from src.core.logger import system_logger, alert_logger

class LogMonitor:
    """
    Tails a log file and searches for suspicious patterns (Regex).
    """
    def __init__(self, log_file=None):
        self.os_type = platform.system()
        
        # Set default log file if none provided
        if not log_file:
            if self.os_type == "Windows":
                self.log_file = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
            else:
                self.log_file = "/var/log/auth.log"
        else:
            self.log_file = log_file

        # OS-specific patterns
        if self.os_type == "Windows":
            self.patterns = {
                r"EventID[=:\s]+4625": "Brute Force Attempt / Failed Login",
                r"EventID[=:\s]+4624": "Successful Login"
            }
        else:
            self.patterns = {
                r"Failed password for": "Brute Force Attempt",
                r"authentication failure": "Auth Failure",
                r"Invalid user": "Unknown User Access",
                r"Accepted password for": "Successful Login"
            }
        self.is_running = False

    def tail_f(self):
        """Generator that yields new lines in a file."""
        if not os.path.exists(self.log_file):
            system_logger.warning(f"Log file {self.log_file} not found. Waiting...")
            while not os.path.exists(self.log_file):
                time.sleep(1)
        
        with open(self.log_file, "r") as f:
            # Go to the end of the file
            f.seek(0, 2)
            while self.is_running:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line

    def start(self):
        self.is_running = True
        system_logger.info(f"[*] Starting HIDS Log Monitor on {self.log_file}...")
        
        # Run in a separate thread
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()

    def _monitor_loop(self):
        for line in self.tail_f():
            self._analyze_line(line)

    def _analyze_line(self, line):
        for pattern, label in self.patterns.items():
            if re.search(pattern, line):
                alert_msg = f"[HIDS ALERT] {label} detected: {line.strip()}"
                alert_logger.warning(alert_msg)
                bus.emit("security_alert", {"type": "LOG_ANALYSIS", "label": label, "line": line.strip()})

    def stop(self):
        self.is_running = False

if __name__ == "__main__":
    # For testing, you could point this to a local mock file
    monitor = LogMonitor("mock_auth.log")
    monitor.start()
    while True:
        time.sleep(1)
