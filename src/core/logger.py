import logging
import os
from datetime import datetime

def setup_logger(name, log_file, level=logging.INFO):
    """Function to setup as many loggers as you want"""
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Ensure logs directory exists
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    except PermissionError:
        print(f"Warning: Permission denied creating {os.path.dirname(log_file)}. Using current directory.")
        log_file = os.path.basename(log_file)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    try:
        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    except PermissionError:
        print(f"Warning: Permission denied writing to {log_file}. Logging to console only.")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger

# Primary logger for general system events
system_logger = setup_logger("IDS_System", "logs/system.log")

# Specific logger for security alerts
alert_logger = setup_logger("IDS_Alert", "logs/alerts.log")
