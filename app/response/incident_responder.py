def respond_to_incident(alert):
    """Determine an incident response action based on alert severity."""

    severity = alert.get("severity", "LOW")

    response = {
        "alert_id": alert.get("alert_id"),
        "severity": severity,
        "action": None,
        "status": alert.get("status", "OPEN"),
        "message": None,
    }

    if severity == "HIGH":
        response["action"] = "BLOCK"
        response["status"] = "INVESTIGATING"
        response["message"] = "High-severity threat detected. Connection should be blocked."

    elif severity == "MEDIUM":
        response["action"] = "MONITOR"
        response["status"] = "INVESTIGATING"
        response["message"] = "Medium-severity threat detected. Continuous monitoring started."

    else:
        response["action"] = "LOG"
        response["status"] = "OPEN"
        response["message"] = "Low-severity event recorded for security review."

    return response