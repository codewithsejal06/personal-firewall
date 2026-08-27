from app.dashboard.statistics import calculate_security_statistics
from app.dashboard.report_generator import generate_security_report
from app.dashboard.alerts import display_recent_alerts
from app.storage.event_viewer import display_event_history


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

    # Step 4: Display recent security alerts
    display_recent_alerts(connections)

    # Step 4: Display stored security event history
    display_event_history()

    print("\n" + "=" * 60)
    print("SECURITY DASHBOARD COMPLETED")
    print("=" * 60)

    return statistics