import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent.parent
CONFIG_FILE = BASE_DIR / "config" / "security_policy.json"


def load_security_policy():
    """
    Load security policies from the JSON configuration file.
    """

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except FileNotFoundError:
        raise FileNotFoundError(
            f"Security configuration file not found: {CONFIG_FILE}"
        )

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in security configuration: {error}"
        )