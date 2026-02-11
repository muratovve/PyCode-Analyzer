import logging
import logging.handlers
import os

def setup_logging(log_file="analyzer.log", level=logging.INFO):
    # Ensure log directory exists
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("analyzer")
    logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates if called multiple times
    if logger.handlers:
        logger.handlers.clear()

    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # File Handler (Rotating)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=1024*1024*5, backupCount=3 # 5MB limit, 3 backups
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console Handler (cleaner output for user)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING) # Only warnings/errors to console by default
    console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(console_handler)

    return logger
