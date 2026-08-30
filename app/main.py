from app.dashboard.dashboard_manager import run_security_dashboard
from app.monitor.monitoring_service import run_live_monitoring_cycle


def main():
    """
    Start the Personal Firewall application.
    """

    print("=" * 60)
    print("PERSONAL FIREWALL & NETWORK SECURITY MONITOR")
    print("System initialized successfully.")
    print("=" * 60)

    print("\nStarting live network monitoring...")

    processed_connections = run_live_monitoring_cycle(
        callback=run_security_dashboard
    )

    print(
        f"\nMonitoring completed successfully. "
        f"Processed {len(processed_connections)} connections."
    )


if __name__ == "__main__":
    main()