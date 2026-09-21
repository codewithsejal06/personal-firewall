from app.response.incident_manager import (
    create_incident,
    get_incident,
    get_all_incidents,
    get_incident_history,
    get_incident_timeline,
    update_incident_status,
    clear_incidents,
    get_incident_summary,
    reload_incidents,
)


def test_create_incident():
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
    }

    incident = create_incident(connection)

    assert incident["incident_id"].startswith("INC-")
    assert incident["severity"] == "HIGH"
    assert incident["remote_address"] == "203.0.113.10:443"
    assert incident["status"] == "INVESTIGATING"


def test_get_incident():
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.20:443",
        "severity": "MEDIUM",
    }

    incident = create_incident(connection)

    result = get_incident(
        incident["incident_id"]
    )

    assert result is not None
    assert result["incident_id"] == incident["incident_id"]


def test_get_all_incidents():
    clear_incidents()

    create_incident({
        "remote_address": "203.0.113.30:443",
        "severity": "HIGH",
    })

    create_incident({
        "remote_address": "203.0.113.31:443",
        "severity": "LOW",
    })

    incidents = get_all_incidents()

    assert len(incidents) == 2


def test_duplicate_active_incident():
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.40:443",
        "severity": "HIGH",
    }

    first_incident = create_incident(connection)
    second_incident = create_incident(connection)

    assert (
        first_incident["incident_id"]
        == second_incident["incident_id"]
    )


def test_update_incident_status():
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.50:443",
        "severity": "HIGH",
    }

    incident = create_incident(connection)

    updated = update_incident_status(
        incident["incident_id"],
        "RESOLVED",
    )

    assert updated["status"] == "RESOLVED"


def test_invalid_incident_status():
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.51:443",
        "severity": "HIGH",
    }

    incident = create_incident(connection)

    try:
        update_incident_status(
            incident["incident_id"],
            "INVALID",
        )
        assert False
    except ValueError:
        assert True


def test_get_incident_summary():
    clear_incidents()

    create_incident({
        "remote_address": "203.0.113.60:443",
        "severity": "HIGH",
    })

    create_incident({
        "remote_address": "203.0.113.61:443",
        "severity": "MEDIUM",
    })

    create_incident({
        "remote_address": "203.0.113.62:443",
        "severity": "LOW",
    })

    summary = get_incident_summary()

    assert summary["total_incidents"] == 3
    assert summary["high_severity"] == 1
    assert summary["medium_severity"] == 1
    assert summary["low_severity"] == 1


def test_incident_response_history():
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.63:443",
        "severity": "HIGH",
    }

    incident = create_incident(connection)

    history = get_incident_history(
        incident["incident_id"]
    )

    assert history is not None
    assert len(history) == 1

    assert (
        history[0]["action"]
        == "BLOCK_AND_INVESTIGATE"
    )

    assert (
        history[0]["status"]
        == "INVESTIGATING"
    )

    assert "timestamp" in history[0]


def test_incident_timeline():
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.70:443",
        "severity": "HIGH",
    }

    incident = create_incident(connection)

    timeline = get_incident_timeline(
        incident["incident_id"]
    )

    assert timeline is not None
    assert len(timeline) == 2

    assert (
        timeline[0]["event"]
        == "INCIDENT_CREATED"
    )

    assert (
        timeline[1]["event"]
        == "BLOCK_AND_INVESTIGATE"
    )

    assert "timestamp" in timeline[0]
    assert "timestamp" in timeline[1]


def test_incident_timeline_after_status_update():
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.71:443",
        "severity": "HIGH",
    }

    incident = create_incident(connection)

    update_incident_status(
        incident["incident_id"],
        "RESOLVED",
    )

    timeline = get_incident_timeline(
        incident["incident_id"]
    )

    assert timeline is not None
    assert len(timeline) == 3

    assert (
        timeline[0]["event"]
        == "INCIDENT_CREATED"
    )

    assert (
        timeline[1]["event"]
        == "BLOCK_AND_INVESTIGATE"
    )

    assert (
        timeline[2]["event"]
        == "STATUS_UPDATE"
    )

    assert (
        timeline[2]["status"]
        == "RESOLVED"
    )


def test_get_incident_history_for_unknown_incident():
    clear_incidents()

    history = get_incident_history(
        "INC-9999"
    )

    assert history is None


def test_get_incident_timeline_for_unknown_incident():
    clear_incidents()

    timeline = get_incident_timeline(
        "INC-9999"
    )

    assert timeline is None


def test_reload_incidents():
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.80:443",
        "severity": "HIGH",
    }

    incident = create_incident(connection)

    incident_id = incident["incident_id"]

    reload_incidents()

    reloaded = get_incident(incident_id)

    assert reloaded is not None
    assert reloaded["incident_id"] == incident_id
    assert "response_history" in reloaded