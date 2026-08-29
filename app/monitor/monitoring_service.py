from app.monitor.connection_collector import collect_active_connections
import time

from app.core.security_pipeline import process_security_connection


def run_monitoring_cycle(
    connections,
    callback=None,
    blocklist_manager=None
):
    """
    Run one monitoring cycle.

    Each connection is processed through the complete
    security pipeline before being sent to the callback.
    """

    print("\nStarting security monitoring cycle...")

    processed_connections = []

    for connection in connections:
        processed_connection = process_security_connection(
            connection,
            blocklist_manager=blocklist_manager,
            save_event=False
        )

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


def start_monitoring(
    connections,
    callback=None,
    cycles=3,
    interval=5,
    blocklist_manager=None
):
    """
    Run security monitoring cycles.

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
                callback=callback,
                blocklist_manager=blocklist_manager
            )

            if cycles is None or cycle < cycles:
                print(
                    f"Waiting {interval} seconds for the next cycle..."
                )
                time.sleep(interval)

            cycle += 1

    except KeyboardInterrupt:
        print("\n\nMonitoring stopped safely by user.")

    finally:
        print("\nReal-time monitoring session completed.")