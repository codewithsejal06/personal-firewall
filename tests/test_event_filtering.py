from app.storage.event_storage import filter_security_events


def test_filter_security_events_by_high_severity():

    events = filter_security_events("HIGH")

    assert isinstance(events, list)

    for event in events:
        assert event.get("severity", "").upper() == "HIGH"


def test_filter_security_events_without_severity():

    events = filter_security_events()

    assert isinstance(events, list)