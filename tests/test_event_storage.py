from app.storage.event_storage import (
    save_security_event,
    load_security_events
)


def test_save_and_load_security_event():
    event = {
        "severity": "HIGH",
        "classification": "SUSPICIOUS",
        "message": "Potential security threat detected."
    }

    saved_event = save_security_event(event)

    events = load_security_events()

    assert saved_event["severity"] == "HIGH"
    assert len(events) >= 1
    