from datetime import datetime


def create_alert(connection):
    """Create a security alert for a detected threat."""

    severity = connection.get("severity", "LOW")
    classification = connection.get("classification", "UNKNOWN")
    remote_address = connection.get("remote_address", "N/A")

    alert = {
        "alert_id": f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": severity,
        "classification": classification,
        "remote_address": remote_address,
        "status": "OPEN",
        "message": "Suspicious network activity detected."
    }

    return alert