from app.response.incident_manager import get_incident_summary

from app.dashboard.statistics import calculate_security_statistics

from app.monitor.security_insights import generate_security_insights


def display_firewall_dashboard(connections, statistics):
    """
    Display the main Firewall Security Dashboard.
    """

    # --------------------------------------------------
    # Direction statistics
    # --------------------------------------------------

    inbound = 0
    outbound = 0

    # --------------------------------------------------
    # Protocol statistics
    # --------------------------------------------------

    tcp = 0
    udp = 0

    for connection in connections:

        direction = str(
            connection.get("direction", "")
        ).upper()

        protocol = str(
            connection.get("protocol", "")
        ).upper()

        if direction == "INBOUND":
            inbound += 1

        elif direction == "OUTBOUND":
            outbound += 1

        if protocol == "TCP":
            tcp += 1

        elif protocol == "UDP":
            udp += 1

    # --------------------------------------------------
    # Security alerts
    # --------------------------------------------------

    alerts_detected = 0

    for connection in connections:

        security_alert = connection.get(
            "security_alert"
        )

        threat_alerts = connection.get(
            "threat_alerts",
            []
        )

        if security_alert:
            alerts_detected += 1

        elif threat_alerts:
            alerts_detected += 1

    # --------------------------------------------------
    # Main Dashboard
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("             FIREWALL SECURITY DASHBOARD")
    print("=" * 60)

    print("\nTRAFFIC OVERVIEW")
    print("-" * 60)

    print(
        f"Total Events: "
        f"{statistics['total_connections']}"
    )

    print(
        f"Allowed: "
        f"{statistics['allowed_connections']}"
    )

    print(
        f"Blocked: "
        f"{statistics['blocked_connections']}"
    )

    print("\nDIRECTION")
    print("-" * 60)

    print(f"OUTBOUND: {outbound}")
    print(f"INBOUND: {inbound}")

    print("\nPROTOCOLS")
    print("-" * 60)

    print(f"TCP: {tcp}")
    print(f"UDP: {udp}")

    # --------------------------------------------------
    # Security alert severity statistics
    # --------------------------------------------------

    low_alerts = 0
    medium_alerts = 0
    high_alerts = 0

    for connection in connections:

        # Severity should only be counted when
        # an actual threat was detected.
        if not connection.get("threat_detected"):
            continue

        severity = str(
            connection.get(
                "severity",
                ""
            )
        ).upper()

        if severity == "LOW":
            low_alerts += 1

        elif severity == "MEDIUM":
            medium_alerts += 1

        elif severity == "HIGH":
            high_alerts += 1

    alerts_detected = (
        low_alerts
        + medium_alerts
        + high_alerts
    )

    print("\nSECURITY ALERTS")
    print("-" * 60)

    print(
        f"Alerts Detected: "
        f"{alerts_detected}"
    )

    print(
        f"LOW: "
        f"{low_alerts}"
    )

    print(
        f"MEDIUM: "
        f"{medium_alerts}"
    )

    print(
        f"HIGH: "
        f"{high_alerts}"
    )

    # --------------------------------------------------
    # Incident Summary
    # --------------------------------------------------

    summary = get_incident_summary()

    print("\nINCIDENTS")
    print("-" * 60)

    print(
        f"Total Incidents: "
        f"{summary['total_incidents']}"
    )

    print(
        f"Open: "
        f"{summary['open_incidents']}"
    )

    print(
        f"Investigating: "
        f"{summary['total_incidents'] - summary['open_incidents'] - summary['resolved_incidents']}"
    )

    print(
        f"Resolved: "
        f"{summary['resolved_incidents']}"
    )

    # --------------------------------------------------
    # Monitoring Status
    # --------------------------------------------------

    print("\nMONITORING STATUS")
    print("-" * 60)

    print(
        f"Connections Processed: "
        f"{len(connections)}"
    )

    print("Status: ACTIVE")

    print("\n" + "=" * 60)


def display_incident_summary():
    """
    Display a detailed summary of security incidents.

    This function is kept for compatibility with
    the existing test suite.
    """

    summary = get_incident_summary()

    print("\n" + "-" * 60)
    print("INCIDENT SUMMARY")
    print("-" * 60)

    print(
        f"Total Incidents    : "
        f"{summary['total_incidents']}"
    )

    print(
        f"Open Incidents     : "
        f"{summary['open_incidents']}"
    )

    print(
        f"Resolved Incidents : "
        f"{summary['resolved_incidents']}"
    )

    print("\nSeverity Breakdown")

    print(
        f"HIGH   : "
        f"{summary['high_severity']}"
    )

    print(
        f"MEDIUM : "
        f"{summary['medium_severity']}"
    )

    print(
        f"LOW    : "
        f"{summary['low_severity']}"
    )

    print("-" * 60)


def display_security_insights(insights):
    """
    Display a summary of security insights.
    """

    print("\n" + "=" * 60)
    print("SECURITY INSIGHTS")
    print("=" * 60)

    print(
        f"Total Connections      : "
        f"{insights['total_connections']}"
    )

    print(
        f"Unique Connections     : "
        f"{insights['unique_connections']}"
    )

    print(
        f"Repeated Connections   : "
        f"{insights['repeated_connections']}"
    )

    print(
        f"Blocked Connections    : "
        f"{insights['blocked_connections']}"
    )

    print(
        f"Threats Detected       : "
        f"{insights['threats_detected']}"
    )

    most_frequent = insights["most_frequent_address"]

    if most_frequent:
        print(
            f"Most Frequent Address  : "
            f"{most_frequent}"
        )
    else:
        print(
            "Most Frequent Address  : N/A"
        )

def run_security_dashboard(connections):
    """
    Run the complete security dashboard workflow.
    """

    # Step 1: Calculate security statistics
    statistics = calculate_security_statistics(
        connections
    )

    # Step 2: Display clean firewall dashboard
    display_firewall_dashboard(
        connections,
        statistics
    )

    # Step 3: Generate security insights
    insights = generate_security_insights(
        connections
    )

    display_security_insights(
        insights
    )

    print("\n" + "=" * 60)
    print("             SECURITY DASHBOARD COMPLETED")
    print("=" * 60)

    return statistics