# Personal Firewall & Network Security Monitor

A Python-based Personal Firewall and Network Security Monitoring system designed to monitor network connections, detect suspicious activity, enforce security rules, generate alerts, and manage security incidents.

## 🚀 Project Overview

The Personal Firewall & Network Security Monitor is a cybersecurity project developed using Python.

The system collects network connection information and processes connections through a security pipeline that includes firewall rule evaluation, blocklist enforcement, threat detection, severity classification, security event generation, incident response, monitoring, and reporting.

The project focuses on practical implementation of network security and SOC-style security monitoring concepts.

## 🔐 Key Features

- Network connection monitoring
- Firewall rule evaluation
- IP address blocking
- Port blocking
- Persistent blocklist
- Threat detection
- Threat severity classification
- Automatic blocking of high-severity threats
- Security event generation and storage
- Alert generation and storage
- Incident management
- Automatic incident response
- Incident status tracking
- Incident response history
- Incident timeline
- Persistent incident storage
- Security monitoring service
- Security dashboard
- Security statistics
- Security report generation
- End-to-end security pipeline
- Automated test suite

## 🛡️ Security Workflow

```text
Network Connection
        ↓
Connection Collection
        ↓
Connection Tracking
        ↓
Blocklist Enforcement
        ↓
Firewall Rule Evaluation
        ↓
Threat Detection
        ↓
Severity Classification
        ↓
Automatic Threat Blocking
        ↓
Security Event & Alert
        ↓
Incident Management
        ↓
Incident Response
        ↓
Monitoring & Dashboard
        ↓
Security Reporting
```

# 🏗️ Project Architecture
```text
                 Network Connections
                         |
                         v
              +----------------------+
              | Connection Collector  |
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Connection Tracking  |
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Blocklist Enforcement|
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Firewall Rule        |
              | Evaluation           |
              +----------+-----------+
                         |
                    +----+----+
                    |         |
                  ALLOW      BLOCK
                    |         |
                    +----+----+
                         |
                         v
              +----------------------+
              | Threat Detection     |
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Severity             |
              | Classification       |
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Automatic Threat     |
              | Blocking             |
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Security Events      |
              | & Alerts              |
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Incident Management  |
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Incident Response    |
              +----------+-----------+
                         |
                         v
              +----------------------+
              | Monitoring Dashboard |
              | & Reporting          |
              +----------------------+          
```

# Project Structure
```text
Personal-firewall/
│
├── app/
│   │
│   ├── alerts/
│   │   ├── ...
│   │
│   ├── config/
│   │   └── ...
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   └── security_pipeline.py
│   │
│   ├── dashboard/
│   │   ├── __init__.py
│   │   ├── alerts.py
│   │   ├── dashboard_manager.py
│   │   ├── report_generator.py
│   │   └── statistics.py
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── threat_blocking.py
│   │   └── threat_detector.py
│   │
│   ├── firewall/
│   │   ├── __init__.py
│   │   ├── blocklist_manager.py
│   │   ├── policy_enforcer.py
│   │   └── rules.py
│   │
│   ├── monitor/
│   │   ├── __init__.py
│   │   ├── connection_collector.py
│   │   ├── connection_monitor.py
│   │   ├── connection_tracker.py
│   │   ├── monitoring_service.py
│   │   ├── security_insights.py
│   │   └── traffic_classifier.py
│   │
│   ├── response/
│   │   ├── __init__.py
│   │   ├── incident_manager.py
│   │   └── incident_responder.py
│   │
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── event_storage.py
│   │   ├── event_viewer.py
│   │   └── incident_storage.py
│   │
│   ├── utils/
│   │   └── __init__.py
│   │
│   └── main.py
│
├── config/
│
├── data/
│   └── security_events.json
│
├── logs/
│   └── firewall_events.log
│
├── tests/
│   ├── test_alert_integration.py
│   ├── test_alert_manager.py
│   ├── test_alert_storage_integration.py
│   ├── test_blocklist_manager.py
│   ├── test_connection_collector.py
│   ├── test_connection_tracker.py
│   ├── test_dashboard_manager.py
│   ├── test_end_to_end.py
│   ├── test_event_filtering.py
│   ├── test_event_storage.py
│   ├── test_event_viewer.py
│   ├── test_firewall_rules.py
│   ├── test_incident_manager.py
│   ├── test_incident_responder.py
│   ├── test_incident_storage.py
│   ├── test_monitor_dashboard_integration.py
│   ├── test_monitoring_service.py
│   ├── test_policy_enforcer.py
│   ├── test_report_generator.py
│   ├── test_security_config.py
│   ├── test_security_insights.py
│   ├── test_security_logger.py
│   ├── test_security_pipeline.py
│   ├── test_statistics.py
│   ├── test_threat_blocking.py
│   └── test_threat_detector.py
│
├── .gitignore
├── README.md
└── requirements.txt
```

# Technologies Used
- Python
- Pytest
- Network Security
- Firewall Rule Evaluation
- Threat Detection
- Incident Response
- Security Monitoring
- JSON-based Persistent Storage
- Modular Python Architecture

## Installation
Clone the repository:
```text
git clone YOUR_GITHUB_REPOSITORY_URL
cd Personal-firewall
```

Create a virtual environment:
```text
python -m venv .venv
```

Activate the virtual environment on Windows PowerShell:
```text
.\.venv\Scripts\Activate.ps1
```

Install the required dependencies:
```text
python -m pip install -r requirements.txt
```

## Running the Project

Start the Personal Firewall monitoring system:
```text
python -m app.main
```
The application starts the monitoring workflow and processes available network connections.

The system collects connection information, evaluates firewall rules, detects threats, records security events, and displays monitoring information.

## Example Output

Example terminal output:
Security Dashboard
```
Total Events Displayed: 605

MEDIUM Severity Events

Remote Address: 198.51.100.50:443

Monitoring cycle completed successfully.

Processed 38 connections.
```
The exact number of connections and events can change depending on the system's current network activity.

# Security Dashboard

The project includes a terminal-based security dashboard that provides information about security events and monitoring activity.

The dashboard can display information such as:

Security Dashboard
--

- Total Security Events
- Threat Severity
- Remote Addresses
- Firewall Decisions
- Security Alerts
- Monitoring Status

# Incident Management

The project includes an incident management system for handling detected security incidents.

Each incident can contain:

- Incident ID
- Severity
- Remote address
- Creation timestamp
- Connection information
- Incident status
- Response action
- Response history
- Incident timeline

Supported incident statuses include:
```
OPEN
INVESTIGATING
RESOLVED
```

## Automatic Incident Response

The incident responder determines the response according to incident severity.
```
HIGH
  ↓
BLOCK_AND_INVESTIGATE
  ↓
INVESTIGATING

MEDIUM
  ↓
INVESTIGATE
  ↓
INVESTIGATING

LOW
  ↓
MONITOR
  ↓
OPEN
```
Response actions are stored as part of the incident response history.