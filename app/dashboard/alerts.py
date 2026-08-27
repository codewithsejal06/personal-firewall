def display_recent_alerts(connections):
    """
    Display recent security alerts from processed connections.
    """

    print("\n" + "=" * 60)
    print("RECENT SECURITY ALERTS")
    print("=" * 60)

    alerts_found = False

    for connection in connections:
        alert = connection.get("security_alert")

        if alert:
            alerts_found = True

            print(f"\nAlert ID      : {alert.get('alert_id')}")
            print(f"Severity      : {alert.get('severity')}")
            print(f"Classification: {alert.get('classification')}")
            print(f"Remote Address: {alert.get('remote_address')}")
            print(f"Status        : {alert.get('status')}")
            print(f"Message       : {alert.get('message')}")

            print("-" * 60)

    if not alerts_found:
        print("\nNo security alerts detected.")