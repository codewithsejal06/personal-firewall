from app.response.incident_manager import get_incident_summary
from app.dashboard.statistics import calculate_security_statistics
from app.dashboard.report_generator import generate_security_report
from app.dashboard.alerts import display_recent_alerts
from app.storage.event_viewer import display_event_history
from app.monitor.security_insights import generate_security_insights


def display_security_insights(insights):
    """
    Display a summary of security insights.
    """

    print("\n" + "=" * 60)
    print("SECURITY INSIGHTS")
    print("=" * 60)

    print(f"Total Connections      : {insights['total_connections']}")
    print(f"Unique Connections     : {insights['unique_connections']}")
    print(f"Repeated Connections   : {insights['repeated_connections']}")
    print(f"Blocked Connections    : {insights['blocked_connections']}")
    print(f"Threats Detected       : {insights['threats_detected']}")

    most_frequent = insights["most_frequent_address"]

    if most_frequent:
        print(f"Most Frequent Address  : {most_frequent}")
    else:
        print("Most Frequent Address  : N/A")


def display_incident_summary():
    """
    Display a summary of security incidents.
    """

    summary = get_incident_summary()

    print("\n" + "-" * 60)
    print("INCIDENT SUMMARY")
    print("-" * 60)

    print(f"Total Incidents    : {summary['total_incidents']}")
    print(f"Open Incidents     : {summary['open_incidents']}")
    print(f"Resolved Incidents : {summary['resolved_incidents']}")

    print("\nSeverity Breakdown")
    print(f"HIGH   : {summary['high_severity']}")
    print(f"MEDIUM : {summary['medium_severity']}")
    print(f"LOW    : {summary['low_severity']}")

    print("-" * 60)


def run_security_dashboard(connections):
    """
    Run the complete security dashboard workflow.
    """

    print("\n" + "=" * 60)
    print("PERSONAL FIREWALL SECURITY DASHBOARD")
    print("=" * 60)

    # Step 1: Calculate security statistics
    statistics = calculate_security_statistics(connections)

    # Step 2: Generate security report
    report = generate_security_report(statistics)

    # Step 3: Display the report
    print(report)

    # Step 4: Display incident summary
    display_incident_summary()

    # Step 5: Display recent security alerts
    display_recent_alerts(connections)

    # Step 6: Display security insights
    insights = generate_security_insights(connections)
    display_security_insights(insights)

    # Step 7: Display stored security event history
    display_event_history()

    print("\n" + "=" * 60)
    print("SECURITY DASHBOARD COMPLETED")
    print("=" * 60)

    return statistics
