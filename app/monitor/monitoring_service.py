import time


def run_monitoring_cycle(connections, callback=None):
    """
    Run one monitoring cycle.

    The callback can be used to update the dashboard
    after processing the current connections.
    """

    print("\nStarting security monitoring cycle...")

    if callback:
        callback(connections)

    print("Monitoring cycle completed.")

    return connections


def start_monitoring(connections, callback=None, cycles=3, interval=5):
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

            run_monitoring_cycle(connections, callback)

            print(
                f"Waiting {interval} seconds for the next cycle..."
            )
            time.sleep(interval)

            cycle += 1

    except KeyboardInterrupt:
        print("\n\nMonitoring stopped safely by user.")

    finally:
        print("\nReal-time monitoring session completed.")