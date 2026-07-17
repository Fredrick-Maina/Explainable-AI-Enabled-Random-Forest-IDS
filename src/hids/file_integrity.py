import hashlib
import os
import json
from src.core.event_bus import bus
from src.core.logger import system_logger, alert_logger

class FileIntegrityMonitor:
    """
    Monitors files and directories for unauthorized changes using SHA-256 hashing.
    """
    def __init__(self, watch_list=None, baseline_file="data/baseline.json"):
        # Default watch list includes core project files and source directory
        self.watch_list = watch_list or ["main.py", "src/"]
        self.baseline_file = baseline_file
        self.hashes = {}
        
        # Load or create baseline
        if os.path.exists(self.baseline_file):
            self.load_baseline()
        else:
            self.create_baseline()

    def calculate_hash(self, filepath):
        """Returns the SHA-256 hash of a file."""
        if not os.path.isfile(filepath):
            return None
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            system_logger.error(f"Error hashing {filepath}: {e}")
            return None

    def _get_all_files(self):
        """Helper to resolve the watch list into a flat list of files."""
        all_files = []
        for path in self.watch_list:
            if os.path.isfile(path):
                all_files.append(path)
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for name in files:
                        all_files.append(os.path.join(root, name))
            else:
                system_logger.warning(f"Watch list item not found: {path}")
        return all_files

    def create_baseline(self):
        """Calculates and saves initial hashes for the watch list."""
        system_logger.info("Creating new HIDS file integrity baseline...")
        self.hashes = {}
        for filepath in self._get_all_files():
            file_hash = self.calculate_hash(filepath)
            if file_hash:
                self.hashes[filepath] = file_hash
        
        baseline_dir = os.path.dirname(self.baseline_file)
        if baseline_dir:
            os.makedirs(baseline_dir, exist_ok=True)
            
        with open(self.baseline_file, "w") as f:
            json.dump(self.hashes, f, indent=4)
        system_logger.info(f"Baseline for {len(self.hashes)} files saved to {self.baseline_file}")

    def load_baseline(self):
        """Loads existing hashes from the baseline file."""
        try:
            with open(self.baseline_file, "r") as f:
                self.hashes = json.load(f)
            system_logger.info(f"Baseline for {len(self.hashes)} files loaded from {self.baseline_file}")
        except Exception as e:
            system_logger.error(f"Failed to load baseline: {e}. Creating new one.")
            self.create_baseline()

    def check_integrity(self):
        """Scans watched files and compares them against the baseline."""
        system_logger.info("Starting integrity scan...")
        violations = []
        current_files = self._get_all_files()
        
        # 1. Check for modifications and deletions
        for filepath, baseline_hash in list(self.hashes.items()):
            if not os.path.exists(filepath):
                violations.append(f"DELETED: {filepath}")
                continue
                
            current_hash = self.calculate_hash(filepath)
            if current_hash != baseline_hash:
                violations.append(f"MODIFIED: {filepath}")

        # 2. Check for new files in watched directories
        for filepath in current_files:
            if filepath not in self.hashes:
                violations.append(f"NEW FILE: {filepath}")

        if violations:
            for v in violations:
                alert_msg = f"[HIDS ALERT] Integrity violation: {v}"
                alert_logger.error(alert_msg)
                bus.emit("security_alert", {"type": "FILE_INTEGRITY", "message": v})
        else:
            system_logger.info("Integrity check passed. No changes detected.")

if __name__ == "__main__":
    fim = FileIntegrityMonitor()
    fim.check_integrity()
