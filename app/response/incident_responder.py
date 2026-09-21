def respond_to_incident(incident):
    """
    Determine the automatic response based on
    incident severity.
    """

    severity = incident.get("severity", "LOW").upper()

    if severity == "HIGH":
        return {
            "action": "BLOCK_AND_INVESTIGATE",
            "status": "INVESTIGATING",
        }

    elif severity == "MEDIUM":
        return {
            "action": "INVESTIGATE",
            "status": "INVESTIGATING",
        }

    else:
        return {
            "action": "MONITOR",
            "status": "OPEN",
        }