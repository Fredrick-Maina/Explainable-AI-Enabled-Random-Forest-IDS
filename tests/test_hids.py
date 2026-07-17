import unittest
import os
import json
import shutil
from unittest.mock import MagicMock, patch
from src.hids.file_integrity import FileIntegrityMonitor

class TestFileIntegrityMonitor(unittest.TestCase):
    @patch('src.core.logger.setup_logger')
    def setUp(self, mock_setup):
        # Mock the loggers to avoid permission issues with /logs
        mock_setup.return_value = MagicMock()
        
        self.test_dir = "test_watch_dir"
        os.makedirs(self.test_dir, exist_ok=True)
        self.test_file = os.path.join(self.test_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("initial content")
        
        self.baseline_file = "test_baseline.json"
        self.fim = FileIntegrityMonitor(watch_list=[self.test_dir], baseline_file=self.baseline_file)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        if os.path.exists(self.baseline_file):
            os.remove(self.baseline_file)

    def test_baseline_creation(self):
        self.assertTrue(os.path.exists(self.baseline_file))
        with open(self.baseline_file, "r") as f:
            hashes = json.load(f)
        self.assertIn(self.test_file, hashes)

    def test_modification_detection(self):
        with open(self.test_file, "w") as f:
            f.write("modified content")
        # Ensure it runs without error (loggers are mocked)
        self.fim.check_integrity()

    def test_new_file_detection(self):
        new_file = os.path.join(self.test_dir, "new.txt")
        with open(new_file, "w") as f:
            f.write("new file")
        self.fim.check_integrity()

    def test_deletion_detection(self):
        os.remove(self.test_file)
        self.fim.check_integrity()

if __name__ == "__main__":
    unittest.main()
