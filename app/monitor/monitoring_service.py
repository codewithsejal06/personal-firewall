import time

from app.monitor.connection_collector import collect_active_connections
from app.monitor.connection_tracker import track_connection
from app.core.security_pipeline import process_security_connection


def run_monitoring_cycle(connections, callback=None):
    """
    Run one monitoring cycle.

    Each connection is processed through the security pipeline
    and then tracked before being sent to the optional callback.
    """

    print("\nStarting security monitoring cycle...")

    processed_connections = []

    for connection in connections:

        # Process the connection through the security pipeline.
        processed_connection = process_security_connection(connection)

        # Track the connection during the current monitoring session.
        tracking_data = track_connection(processed_connection)

        # Add tracking information to the processed connection.
        processed_connection["tracking"] = tracking_data

        processed_connections.append(processed_connection)

    if callback:
        callback(processed_connections)

    print("Monitoring cycle completed.")

    return processed_connections


def run_live_monitoring_cycle(callback=None):
    """
    Collect current live network connections and process them
    through the existing security monitoring cycle.
    """

    print("\nCollecting live network connections...")

    connections = collect_active_connections()

    print(f"Collected {len(connections)} active connections.")

    return run_monitoring_cycle(
        connections,
        callback=callback
    )


def start_monitoring(connections, callback=None, cycles=3, interval=5):
    """
    Run security monitoring cycles using the provided connections.

    Set cycles=None for continuous monitoring.
    Press Ctrl + C to stop safely.
    """

    cycle = 1

    try:
        while cycles is None or cycle <= cycles:

            cycle_label = (
                f"{cycle}/{cycles}"
                if cycles is not None
                else str(cycle)
            )

            print(f"\n{'=' * 60}")
            print(f"MONITORING CYCLE {cycle_label}")
            print("=" * 60)

            run_monitoring_cycle(
                connections,
                callback=callback
            )

            if cycles is None or cycle < cycles:
                print(
                    f"Waiting {interval} seconds "
                    "for the next monitoring cycle..."
                )
                time.sleep(interval)

            cycle += 1

    except KeyboardInterrupt:
        print("\n\nMonitoring stopped safely by user.")

    finally:
        print("\nReal-time monitoring session completed.")


def start_live_monitoring(callback=None, cycles=3, interval=5):
    """
    Run continuous live network monitoring.

    Fresh active network connections are collected during
    every monitoring cycle.

    Set cycles=None for continuous monitoring.
    Press Ctrl + C to stop safely.
    """

    cycle = 1

    try:
        while cycles is None or cycle <= cycles:

            cycle_label = (
                f"{cycle}/{cycles}"
                if cycles is not None
                else str(cycle)
            )

            print(f"\n{'=' * 60}")
            print(f"LIVE MONITORING CYCLE {cycle_label}")
            print("=" * 60)

            run_live_monitoring_cycle(callback=callback)

            if cycles is None or cycle < cycles:
                print(
                    f"Waiting {interval} seconds "
                    "for the next live monitoring cycle..."
                )
                time.sleep(interval)

            cycle += 1

    except KeyboardInterrupt:
        print("\n\nLive monitoring stopped safely by user.")

    finally:
        print("\nContinuous live monitoring session completed.")