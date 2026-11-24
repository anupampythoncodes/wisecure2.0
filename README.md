# WiSecure 2.0
### Machine Learning-Based Network Security Monitoring System

WiSecure 2.0 is a Python-based network security monitoring prototype that captures local network traffic, creates flow records, detects anomalous network behavior using machine learning, and presents security information through a Flask dashboard.

## Features

- Live packet capture using Scapy and Npcap
- Network flow tracking and persistent flow records
- Machine learning-based anomaly detection using Isolation Forest
- Security event correlation
- Security alerts and notification center
- Network analytics and attack timeline
- IP investigation and threat intelligence views
- Incident reporting and PDF report generation

## Technology Stack

- Python
- Flask
- Scapy
- Npcap
- Pandas and NumPy
- Scikit-learn
- Isolation Forest
- ReportLab
- HTML, CSS and JavaScript

## Project Structure

```text
WiSecure-2.0/
│
├── app.py
├── persistent_flow_tracker.py
├── interface_manager.py
├── event_correlation.py
├── wisecure_isolation_forest.pkl
├── requirements.txt
├── .gitignore
│
├── static/
│   └── wisecure_notifications.js
│
└── templates/
    ├── alerts.html
    ├── analytics.html
    ├── attack_timeline.html
    ├── dashboard.html
    ├── ip_investigation.html
    ├── notifications.html
    ├── report_generator.html
    └── threat_intel.html
```

## Requirements

- Windows operating system
- Python 3.10 or a compatible Python version
- Npcap installed
- Administrator privileges may be required for packet capture

## Installation

Clone the repository:

```bash
git clone https://github.com/anupampythoncodes/wisecure2.0.git
cd wisecure2.0
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Install Npcap separately from its official website:
https://npcap.com/

## Running WiSecure

WiSecure uses two separate processes.

### Terminal 1: Start the network flow tracker

Open PowerShell in the project directory:

```powershell
python persistent_flow_tracker.py
```

The tracker selects an available Npcap network interface, captures packets, and maintains persistent flow records.

### Terminal 2: Start the Flask dashboard

Open another PowerShell window:

```powershell
cd D:\WiSecure-Upload
python app.py
```

Open the dashboard:

http://127.0.0.1:5000

Keep both processes running while monitoring network traffic.

Press `CTRL+C` in the tracker terminal to stop packet capture.

## Generated Runtime Files

The application generates runtime data, including flow records, alert history, notification data, and reports.

These files are intentionally excluded from Git using `.gitignore`.

The Isolation Forest model file is included in the repository.

## Important Notes

- WiSecure monitors traffic visible to the selected local network interface. It is not a router-wide monitoring solution.
- An anomaly is an indication of unusual behavior, not proof of a confirmed cyberattack.
- Detection results depend on the model, captured traffic, and configured detection logic.
- This project is intended for educational, research, and experimental network security monitoring.
- Only monitor networks and devices for which you have authorization.

## Future Improvements

- Extended behavioral analysis
- Improved anomaly detection and validation
- Additional threat intelligence integrations
- Enhanced incident investigation
- More comprehensive testing and evaluation

## Author

Anupam Singh

GitHub: https://github.com/anupampythoncodes
