from app.firewall.rules import evaluate_connection
from app.firewall.policy_enforcer import enforce_blocklist
from app.detection.threat_detector import detect_threat
from app.detection.threat_blocking import automatically_block_threat
from app.storage.event_storage import save_security_event


def process_security_connection(
    connection,
    blocklist_manager=None,
    save_event=True
):
    """
    Process a connection through the complete security pipeline.

    Workflow:
    1. Check the persistent blocklist.
    2. Evaluate firewall rules.
    3. Detect threats.
    4. Automatically block high-severity threats.
    5. Save detected threats as security events.
    """

    processed_connection = connection.copy()

    # ---------------------------------------------------------
    # STEP 1: Persistent blocklist enforcement
    # ---------------------------------------------------------
    processed_connection = enforce_blocklist(
        processed_connection,
        blocklist_manager
    )

    # ---------------------------------------------------------
    # STEP 2: Firewall rule evaluation
    # ---------------------------------------------------------
    firewall_result = evaluate_connection(processed_connection)

    # Important: A persistent blocklist decision must not
    # accidentally be overwritten by the default firewall rule.
    if processed_connection.get("firewall_decision") != "BLOCK":
        processed_connection["firewall_decision"] = (
            firewall_result["decision"]
        )
        processed_connection["firewall_reason"] = (
            firewall_result["reason"]
        )

    # ---------------------------------------------------------
    # STEP 3: Threat detection
    # ---------------------------------------------------------
    threat_result = detect_threat(processed_connection)

    processed_connection["threat_detected"] = (
        threat_result["threat_detected"]
    )
    processed_connection["severity"] = threat_result["severity"]
    processed_connection["threat_alerts"] = threat_result["alerts"]

    # ---------------------------------------------------------
    # STEP 4: Automatic blocking for high-severity threats
    # ---------------------------------------------------------
    blocking_result = automatically_block_threat(
        processed_connection,
        blocklist_manager
    )

    processed_connection["automatic_blocking"] = blocking_result

    # ---------------------------------------------------------
    # STEP 5: Save detected threats as security events
    # ---------------------------------------------------------
    if save_event and processed_connection["threat_detected"]:

        security_event = {
            "severity": processed_connection["severity"],
            "remote_address": processed_connection.get(
                "remote_address",
                "N/A"
            ),
            "firewall_decision": processed_connection.get(
                "firewall_decision",
                "N/A"
            ),
            "alerts": processed_connection["threat_alerts"],
            "automatic_blocking": blocking_result,
        }

        save_security_event(security_event)

    return processed_connection