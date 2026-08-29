import json
import ipaddress
from pathlib import Path

from app.config.security_config import CONFIG_FILE


class BlocklistManager:
    """
    Manage dynamically blocked IP addresses.
    """

    def __init__(self, config_file=CONFIG_FILE):
        self.config_file = Path(config_file)

    def load_policy(self):
        """
        Load the current security policy.
        """

        with open(self.config_file, "r", encoding="utf-8") as file:
            return json.load(file)

    def save_policy(self, policy):
        """
        Save the updated security policy.
        """

        with open(self.config_file, "w", encoding="utf-8") as file:
            json.dump(policy, file, indent=4)

    def add_blocked_ip(self, ip_address):
        """
        Add an IP address to the blocked IP list.
        """

        ipaddress.ip_address(ip_address)

        policy = self.load_policy()

        blocked_ips = policy.setdefault("blocked_ips", [])

        if ip_address not in blocked_ips:
            blocked_ips.append(ip_address)
            self.save_policy(policy)
            return True

        return False

    def remove_blocked_ip(self, ip_address):
        """
        Remove an IP address from the blocked IP list.
        """

        policy = self.load_policy()

        blocked_ips = policy.setdefault("blocked_ips", [])

        if ip_address in blocked_ips:
            blocked_ips.remove(ip_address)
            self.save_policy(policy)
            return True

        return False

    def is_ip_blocked(self, ip_address):
        """
        Check whether an IP address is currently blocked.
        """

        policy = self.load_policy()

        blocked_ips = policy.get("blocked_ips", [])

        return ip_address in blocked_ips

    def get_blocked_ips(self):
        """
        Return all currently blocked IP addresses.
        """

        policy = self.load_policy()

        return policy.get("blocked_ips", [])