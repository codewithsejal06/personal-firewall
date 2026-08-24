import logging
from pathlib import Path


# Find the project root directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Create the logs directory if it does not already exist.
LOG_DIRECTORY = PROJECT_ROOT / "logs"
LOG_DIRECTORY.mkdir(exist_ok=True)

LOG_FILE = LOG_DIRECTORY / "firewall_events.log"


def get_security_logger():
    """
    Create and return the application's security event logger.
    """
    logger = logging.getLogger("personal_firewall")
    logger.setLevel(logging.INFO)

    # Prevent duplicate log entries if the module is imported multiple times.
    if logger.handlers:
        return logger

    file_handler = logging.FileHandler(
        LOG_FILE,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


security_logger = get_security_logger()


def log_firewall_event(connection):
    """
    Record a firewall decision as a security event.
    """

    message = (
        f"Protocol={connection['protocol']} | "
        f"Local={connection['local_address']} | "
        f"Remote={connection['remote_address']} | "
        f"Classification={connection['classification']} | "
        f"Decision={connection['firewall_decision']} | "
        f"Reason={connection['firewall_reason']}"
    )

    security_logger.info(message)