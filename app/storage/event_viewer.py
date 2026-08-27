from app.storage.event_storage import filter_security_events


def format_security_event(event):
    """
    Format a single security event into readable text.
    """

    return (
        f"\n{'-' * 60}\n"
        f"Alert ID       : {event.get('alert_id', 'N/A')}\n"
        f"Timestamp      : {event.get('timestamp', 'N/A')}\n"
        f"Severity       : {event.get('severity', 'N/A')}\n"
        f"Classification : {event.get('classification', 'N/A')}\n"
        f"Remote Address : {event.get('remote_address', 'N/A')}\n"
        f"Status         : {event.get('status', 'N/A')}\n"
        f"Message        : {event.get('message', 'N/A')}\n"
        f"{'-' * 60}"
    )


def display_event_history(severity=None):
    """
    Display stored security events.
    Optionally filter events by severity.
    """

    events = filter_security_events(severity)

    print("\n" + "=" * 60)
    print("PERSONAL FIREWALL SECURITY EVENT HISTORY")
    print("=" * 60)

    if severity:
        print(f"Filter: {severity.upper()} severity events")

    if not events:
        print("\nNo security events found.")
        return

    for event in events:
        print(format_security_event(event))

    print(f"\nTotal Events Displayed: {len(events)}")