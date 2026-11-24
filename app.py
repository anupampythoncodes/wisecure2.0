
import os
import socket
import platform
import ipaddress
import hashlib
import uuid
from event_correlation import correlate_security_events
from flask import jsonify
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import joblib
import numpy as np
import pandas as pd

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file
)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.enums import TA_CENTER


app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FLOW_FILE = os.path.join(BASE_DIR, "persistent_flow_records_v2.csv")
MODEL_FILE = os.path.join(BASE_DIR, "wisecure_isolation_forest.pkl")
ALERT_FILE = os.path.join(BASE_DIR, "wisecure_alert_history.csv")

# --------------------------------------------------
# GENERAL SETTINGS
# --------------------------------------------------

MAX_DISPLAY_FLOWS = 2000
MAX_TABLE_ROWS = 25
MAX_ALERT_HISTORY = 5000
MAX_ALERT_PAGE_ROWS = 200

FEATURES = [
    "protocol",
    "lower_port",
    "higher_port",
    "flow_duration_us",
    "total_packets",
    "total_bytes",
    "packet_length_mean",
    "flow_packet_rate"
]

ALERT_COLUMNS = [
    "alert_id",
    "alert_detected_at",
    "first_seen",
    "protocol",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "model_prediction",
    "hybrid_score",
    "hybrid_risk",
    "anomaly_score",
    "detection_explanation"
]

# --------------------------------------------------
# INCIDENT REPORT STORAGE
# --------------------------------------------------

REPORT_DIR = os.path.join(BASE_DIR, "incident_reports")
REPORT_HISTORY_FILE = os.path.join(REPORT_DIR, "report_history.csv")

os.makedirs(REPORT_DIR, exist_ok=True)

REPORT_HISTORY_COLUMNS = [
    "report_id",
    "generated_at",
    "investigated_ip",
    "total_flows",
    "high",
    "medium",
    "low",
    "info",
    "pdf_file",
    "csv_file"
]

# --------------------------------------------------
# AUTOMATED NOTIFICATION STORAGE
# --------------------------------------------------

NOTIFICATION_FILE = os.path.join(
    BASE_DIR,
    "wisecure_notifications.csv"
)

NOTIFICATION_COLUMNS = [
    "notification_id",
    "created_at",
    "alert_detected_at",
    "source_ip",
    "destination_ip",
    "protocol",
    "risk_level",
    "hybrid_score",
    "reason",
    "is_read"
]


# --------------------------------------------------
# MODEL LOADING
# --------------------------------------------------

model = None

if os.path.exists(MODEL_FILE):
    try:
        model = joblib.load(MODEL_FILE)
        print("[WiSecure] Isolation Forest loaded.")
    except Exception as error:
        print("[WiSecure] Model loading error:", error)
else:
    print("[WiSecure] WARNING: Isolation Forest not found.")


# --------------------------------------------------
# NETWORK INFORMATION
# --------------------------------------------------

def get_network_info():

    try:
        hostname = socket.gethostname()
        addresses = socket.gethostbyname_ex(hostname)[2]

        valid_addresses = [
            address for address in addresses
            if not address.startswith("127.")
        ]

        ip_address = (
            valid_addresses[0]
            if valid_addresses
            else "Unavailable"
        )

    except Exception:
        hostname = socket.gethostname()
        ip_address = "Unavailable"

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "os": platform.system() + " " + platform.release()
    }


# --------------------------------------------------
# mDNS RECOGNITION
# --------------------------------------------------

def is_mdns(row):

    if row["protocol"] != "UDP":
        return False

    ports = {
        row["source_port"],
        row["destination_port"]
    }

    if 5353 not in ports:
        return False

    destination = str(row["destination_ip"]).strip()

    try:
        address = ipaddress.ip_address(destination)

        return (
            address.is_multicast
            and destination in ["224.0.0.251", "ff02::fb"]
        )

    except ValueError:
        return False


# --------------------------------------------------
# PERSISTENT ALERT HISTORY
# --------------------------------------------------

def save_alert_history(flows):

    alerts = flows[
        flows["hybrid_risk"].isin(["HIGH", "MEDIUM"])
    ].copy()

    if alerts.empty:
        return 0

    if os.path.exists(ALERT_FILE):
        try:
            history = pd.read_csv(ALERT_FILE)
            history = history.reindex(columns=ALERT_COLUMNS)

        except Exception as error:
            print("[WiSecure] Alert history read error:", error)
            history = pd.DataFrame(columns=ALERT_COLUMNS)

    else:
        history = pd.DataFrame(columns=ALERT_COLUMNS)

    existing_ids = set(
        history["alert_id"].dropna().astype(str)
    )

    new_records = []

    for _, row in alerts.iterrows():

        fingerprint_data = "|".join([
            str(row.get("first_seen", "")),
            str(row.get("protocol", "")),
            str(row.get("source_ip", "")),
            str(row.get("destination_ip", "")),
            str(row.get("source_port", "")),
            str(row.get("destination_port", "")),
            str(row.get("flow_duration_us", "")),
            str(row.get("total_packets", "")),
            str(row.get("total_bytes", ""))
        ])

        alert_id = hashlib.sha256(
            fingerprint_data.encode("utf-8")
        ).hexdigest()

        if alert_id in existing_ids:
            continue

        record = {
            "alert_id": alert_id,
            "alert_detected_at": datetime.now(timezone.utc).isoformat(),
            "first_seen": row.get("first_seen", ""),
            "protocol": row.get("protocol", ""),
            "source_ip": row.get("source_ip", ""),
            "destination_ip": row.get("destination_ip", ""),
            "source_port": row.get("source_port", ""),
            "destination_port": row.get("destination_port", ""),
            "model_prediction": row.get("model_prediction", ""),
            "hybrid_score": row.get("hybrid_score", 0),
            "hybrid_risk": row.get("hybrid_risk", ""),
            "anomaly_score": row.get("anomaly_score", ""),
            "detection_explanation": row.get(
                "detection_explanation", ""
            )
        }

        new_records.append(record)
        existing_ids.add(alert_id)

    if not new_records:
        return 0

    new_df = pd.DataFrame(new_records, columns=ALERT_COLUMNS)

    history = pd.concat(
        [history, new_df],
        ignore_index=True
    )

    history = history.drop_duplicates(
        subset=["alert_id"],
        keep="last"
    ).tail(MAX_ALERT_HISTORY)

    temp_file = ALERT_FILE + ".tmp"

    try:
        history.to_csv(temp_file, index=False)
        os.replace(temp_file, ALERT_FILE)

    except Exception as error:
        print("[WiSecure] Could not save alert history:", error)

        if os.path.exists(temp_file):
            os.remove(temp_file)

        return 0

    print(f"[WiSecure] Saved {len(new_records)} new alerts.")

    generated = generate_threat_notifications()

    print(
        f"[WiSecure] Notifications generated: {generated}"
    )

    return len(new_records)


# --------------------------------------------------
# AUTOMATED THREAT NOTIFICATION GENERATOR
# --------------------------------------------------


def generate_threat_notifications():
    """
    Generate persistent notifications for new HIGH and MEDIUM alerts.
    Uses alert_id to prevent duplicates.
    """

    if not os.path.exists(ALERT_FILE):
        return 0

    try:
        alerts = pd.read_csv(ALERT_FILE)

        if alerts.empty or "hybrid_risk" not in alerts.columns:
            return 0

        important_alerts = alerts[
            alerts["hybrid_risk"]
            .astype(str)
            .str.upper()
            .isin(["HIGH", "MEDIUM"])
        ].copy()

        if os.path.exists(NOTIFICATION_FILE):
            notifications = pd.read_csv(NOTIFICATION_FILE)
            notifications = notifications.reindex(
                columns=NOTIFICATION_COLUMNS
            )
        else:
            notifications = pd.DataFrame(
                columns=NOTIFICATION_COLUMNS
            )

        existing_ids = set(
            notifications["notification_id"]
            .dropna()
            .astype(str)
        )

        new_notifications = []

        for _, alert in important_alerts.iterrows():

            alert_id = str(alert.get("alert_id", "")).strip()

            if not alert_id or alert_id.lower() == "nan":
                continue

            if alert_id in existing_ids:
                continue

            risk = str(alert.get("hybrid_risk", "")).upper()

            record = {
                "notification_id": alert_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "alert_detected_at": alert.get("alert_detected_at", ""),
                "source_ip": alert.get("source_ip", ""),
                "destination_ip": alert.get("destination_ip", ""),
                "protocol": alert.get("protocol", ""),
                "risk_level": risk,
                "hybrid_score": alert.get("hybrid_score", 0),
                "reason": alert.get("detection_explanation", ""),
                "is_read": False
            }

            new_notifications.append(record)
            existing_ids.add(alert_id)

        if not new_notifications:
            return 0

        updated = pd.concat(
            [
                notifications,
                pd.DataFrame(
                    new_notifications,
                    columns=NOTIFICATION_COLUMNS
                )
            ],
            ignore_index=True
        )

        updated = updated.drop_duplicates(
            subset=["notification_id"],
            keep="last"
        ).tail(5000)

        temp_file = NOTIFICATION_FILE + ".tmp"

        updated.to_csv(temp_file, index=False)
        os.replace(temp_file, NOTIFICATION_FILE)

        print(
            f"[WiSecure] Generated "
            f"{len(new_notifications)} notification(s)."
        )

        return len(new_notifications)

    except Exception as error:
        print("[WiSecure] Notification generation error:", error)
        return 0


# --------------------------------------------------
# MAIN HYBRID DETECTION
# --------------------------------------------------

def process_flows():

    if model is None:
        return pd.DataFrame(), {
            "error": "Isolation Forest model is missing."
        }

    if not os.path.exists(FLOW_FILE):
        return pd.DataFrame(), {
            "error": "Flow data file not found. Start the network tracker."
        }

    try:
        df = pd.read_csv(FLOW_FILE)

    except Exception as error:
        return pd.DataFrame(), {
            "error": f"Could not read flow data: {error}"
        }

    if df.empty:
        return pd.DataFrame(), {
            "error": "Waiting for network flows..."
        }

    required = [
        "protocol",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "first_seen",
        "flow_duration_us",
        "total_packets",
        "total_bytes",
        "packet_length_mean",
        "flow_packet_rate",
        "initiator_detected",
        "flow_status"
    ]

    missing = [
        column for column in required
        if column not in df.columns
    ]

    if missing:
        return pd.DataFrame(), {
            "error": "Missing tracker columns: " + ", ".join(missing)
        }

    df = df.tail(MAX_DISPLAY_FLOWS).copy()
    df.reset_index(drop=True, inplace=True)

    # --------------------------------------------------
    # DATA PREPROCESSING
    # --------------------------------------------------

    numeric_columns = [
        "source_port",
        "destination_port",
        "flow_duration_us",
        "total_packets",
        "total_bytes",
        "packet_length_mean",
        "flow_packet_rate"
    ]

    for column in numeric_columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    df["protocol"] = (
        df["protocol"].astype(str).str.upper()
    )

    df["first_seen_dt"] = pd.to_datetime(
        df["first_seen"],
        errors="coerce",
        utc=True
    )

    initiator = (
        df["initiator_detected"]
        .astype(str)
        .str.strip()
        .str.lower()
        .isin(["true", "1", "yes"])
    )

    mask = (
        df["flow_status"].astype(str).str.upper().eq("COMPLETED")
        & (df["flow_duration_us"] > 0)
        & (df["total_packets"] >= 2)
        & df["protocol"].isin(["TCP", "UDP"])
        & ((df["protocol"] != "TCP") | initiator)
        & df["first_seen_dt"].notna()
    )

    live = df.loc[mask].copy()

    if live.empty:
        return live, {
            "error": "No eligible completed flows yet."
        }

    # --------------------------------------------------
    # FEATURE ENGINEERING
    # --------------------------------------------------

    live["lower_port"] = live[
        ["source_port", "destination_port"]
    ].min(axis=1)

    live["higher_port"] = live[
        ["source_port", "destination_port"]
    ].max(axis=1)

    X = live[FEATURES].copy()

    for column in FEATURES:
        if column != "protocol":
            X[column] = pd.to_numeric(
                X[column],
                errors="coerce"
            )

    X = X.replace([np.inf, -np.inf], np.nan)

    valid = X.notna().all(axis=1)

    live = live.loc[valid].copy()
    X = X.loc[valid]

    if X.empty:
        return live, {
            "error": "No valid model features available."
        }

    # --------------------------------------------------
    # ISOLATION FOREST
    # --------------------------------------------------

    predictions = model.predict(X)
    decision_scores = model.decision_function(X)

    live["anomaly_score"] = -decision_scores
    live["ml_anomaly"] = predictions == -1

    live["model_prediction"] = np.where(
        live["ml_anomaly"],
        "ANOMALY",
        "NORMAL"
    )

    # --------------------------------------------------
    # BEHAVIORAL RULES
    # --------------------------------------------------

    live["behavioral_reasons"] = ""

    def add_reason(index, reason):

        existing = live.at[index, "behavioral_reasons"]

        if existing:
            live.at[index, "behavioral_reasons"] = (
                existing + "; " + reason
            )
        else:
            live.at[index, "behavioral_reasons"] = reason

    for index, row in live.iterrows():

        if row["flow_packet_rate"] >= 1000:
            add_reason(index, "HIGH_PACKET_RATE")

        if row["total_bytes"] >= 10_000_000:
            add_reason(index, "LARGE_DATA_TRANSFER")

        if row["total_packets"] >= 10_000:
            add_reason(index, "HIGH_PACKET_COUNT")

        if row["flow_duration_us"] >= 300_000_000:
            add_reason(index, "LONG_RUNNING_FLOW")

    # --------------------------------------------------
    # POSSIBLE PORT SCANNING
    # --------------------------------------------------

    scan_data = live.dropna(
        subset=[
            "source_ip",
            "destination_port",
            "first_seen_dt"
        ]
    ).copy()

    if not scan_data.empty:

        scan_data["time_window"] = (
            scan_data["first_seen_dt"].dt.floor("60s")
        )

        for _, group in scan_data.groupby(
            ["source_ip", "time_window"]
        ):

            if (
                len(group) >= 20
                and group["destination_port"].nunique() >= 15
            ):

                for index in group.index:
                    add_reason(index, "POSSIBLE_PORT_SCAN")

    # --------------------------------------------------
    # POSSIBLE DESTINATION BURST
    # --------------------------------------------------

    burst_data = live.dropna(
        subset=[
            "source_ip",
            "destination_ip",
            "first_seen_dt"
        ]
    ).copy()

    if not burst_data.empty:

        burst_data["time_window"] = (
            burst_data["first_seen_dt"].dt.floor("10s")
        )

        for _, group in burst_data.groupby(
            ["destination_ip", "time_window"]
        ):

            if (
                len(group) >= 30
                and group["source_ip"].nunique() >= 10
            ):

                for index in group.index:
                    add_reason(index, "POSSIBLE_DESTINATION_BURST")

    # --------------------------------------------------
    # REFINED HYBRID CLASSIFICATION
    # --------------------------------------------------

    live["is_mdns"] = live.apply(is_mdns, axis=1)

    def classify(row):

        reasons = [
            reason.strip()
            for reason in row["behavioral_reasons"].split(";")
            if reason.strip()
        ]

        corroborated = any(
            reason in [
                "POSSIBLE_PORT_SCAN",
                "POSSIBLE_DESTINATION_BURST"
            ]
            for reason in reasons
        )

        behavior = len(reasons) > 0

        if row["is_mdns"] and not corroborated:
            return "INFO"

        if row["ml_anomaly"] and corroborated:
            return "HIGH"

        if row["ml_anomaly"] or behavior:
            return "MEDIUM"

        return "LOW"

    live["hybrid_risk"] = live.apply(
        classify,
        axis=1
    )

    # --------------------------------------------------
    # HYBRID SCORE
    # --------------------------------------------------

    def calculate_score(row):

        if row["hybrid_risk"] in ["LOW", "INFO"]:
            return 0

        score = 0

        if row["ml_anomaly"]:
            score += 40

        if row["behavioral_reasons"]:
            score += 20

        if (
            "POSSIBLE_PORT_SCAN" in row["behavioral_reasons"]
            or "POSSIBLE_DESTINATION_BURST"
            in row["behavioral_reasons"]
        ):
            score += 40

        return min(score, 100)

    live["hybrid_score"] = live.apply(
        calculate_score,
        axis=1
    )

    # --------------------------------------------------
    # DETECTION EXPLANATIONS
    # --------------------------------------------------

    def explain(row):

        findings = []

        if row["is_mdns"]:
            findings.append("STANDARD_MDNS_MULTICAST")

        if row["ml_anomaly"]:
            findings.append("ISOLATION_FOREST_ANOMALY")

        if row["behavioral_reasons"]:
            findings.extend(
                item.strip()
                for item in row["behavioral_reasons"].split(";")
                if item.strip()
            )

        return (
            "; ".join(findings)
            if findings
            else "No detection rules triggered"
        )

    live["detection_explanation"] = live.apply(
        explain,
        axis=1
    )

    # --------------------------------------------------
    # SAVE ALERTS AND GENERATE NOTIFICATIONS
    # --------------------------------------------------

    save_alert_history(live)

    new_notifications = generate_threat_notifications()

    if new_notifications:
        print(
            f"[WiSecure] {new_notifications} new HIGH-risk "
            "notification(s) generated."
        )

    # --------------------------------------------------
    # DASHBOARD SUMMARY
    # --------------------------------------------------

    summary = {
        "total_flows": len(df),
        "eligible_flows": len(live),
        "total_packets": int(live["total_packets"].sum()),
        "ml_anomalies": int(live["ml_anomaly"].sum()),
        "behavioral_findings": int(
            live["behavioral_reasons"].ne("").sum()
        ),
        "high": int((live["hybrid_risk"] == "HIGH").sum()),
        "medium": int((live["hybrid_risk"] == "MEDIUM").sum()),
        "low": int((live["hybrid_risk"] == "LOW").sum()),
        "info": int((live["hybrid_risk"] == "INFO").sum()),
        "packet_rate": round(
            float(live["flow_packet_rate"].max()), 2
        ),
        "last_updated": str(live["first_seen_dt"].max())
    }

    return live, summary


# --------------------------------------------------
# MAIN DASHBOARD
# --------------------------------------------------

@app.route("/")
def dashboard():

    flows, summary = process_flows()
    network_info = get_network_info()

    if not flows.empty:

        display_columns = [
            "first_seen",
            "protocol",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "model_prediction",
            "hybrid_score",
            "hybrid_risk",
            "detection_explanation"
        ]

        recent_flows = (
            flows.sort_values(
                "first_seen_dt",
                ascending=False
            )
            .head(MAX_TABLE_ROWS)[display_columns]
            .replace({np.nan: ""})
            .to_dict(orient="records")
        )

        chart_data = (
            flows.sort_values("first_seen_dt")
            .tail(20)
        )

        history = {
            "labels": [
                str(value)[11:19]
                for value in chart_data["first_seen"]
            ],
            "rates": [
                round(float(value), 2)
                for value in chart_data["flow_packet_rate"]
            ]
        }

    else:
        recent_flows = []
        history = {"labels": [], "rates": []}

    # Notification count for dashboard navigation.
    unread_count = get_unread_notification_count()

    return render_template(
        "dashboard.html",
        network=network_info,
        summary=summary,
        flows=recent_flows,
        history=history,
        unread_count=unread_count
    )


# --------------------------------------------------
# NOTIFICATION COUNT HELPER
# --------------------------------------------------

def get_unread_notification_count():

    if not os.path.exists(NOTIFICATION_FILE):
        return 0

    try:
        data = pd.read_csv(NOTIFICATION_FILE)

        if data.empty or "is_read" not in data.columns:
            return 0

        read_values = (
            data["is_read"]
            .astype(str)
            .str.strip()
            .str.lower()
            .isin(["true", "1", "yes"])
        )

        return int((~read_values).sum())

    except Exception as error:
        print("[WiSecure] Notification count error:", error)
        return 0


# --------------------------------------------------
# THREAT NOTIFICATIONS PAGE
# --------------------------------------------------

@app.route("/notifications")
def notifications():

    # Process flows to check for newly generated HIGH alerts.
    process_flows()

    notification_records = []
    unread_count = 0

    if os.path.exists(NOTIFICATION_FILE):

        try:
            notification_data = pd.read_csv(
                NOTIFICATION_FILE
            )

            notification_data = notification_data.reindex(
                columns=NOTIFICATION_COLUMNS
            )

            if not notification_data.empty:

                notification_data["is_read"] = (
                    notification_data["is_read"]
                    .astype(str)
                    .str.strip()
                    .str.lower()
                    .isin(["true", "1", "yes"])
                )

                unread_count = int(
                    (~notification_data["is_read"]).sum()
                )

                notification_data = notification_data.sort_values(
                    "created_at",
                    ascending=False
                )

                notification_records = (
                    notification_data
                    .fillna("")
                    .to_dict(orient="records")
                )

        except Exception as error:
            print("[WiSecure] Notification page error:", error)

    return render_template(
        "notifications.html",
        notifications=notification_records,
        unread_count=unread_count
    )


# --------------------------------------------------
# MARK INDIVIDUAL NOTIFICATION AS READ
# --------------------------------------------------

@app.route(
    "/notifications/mark-read/<notification_id>",
    methods=["POST"]
)
def mark_notification_read(notification_id):

    if not os.path.exists(NOTIFICATION_FILE):
        return redirect(url_for("notifications"))

    try:
        notification_data = pd.read_csv(
            NOTIFICATION_FILE
        )

        if not notification_data.empty:

            notification_data.loc[
                notification_data["notification_id"]
                .astype(str)
                == str(notification_id),
                "is_read"
            ] = True

            notification_data.to_csv(
                NOTIFICATION_FILE,
                index=False
            )

    except Exception as error:
        print("[WiSecure] Mark notification read error:", error)

    return redirect(url_for("notifications"))


# --------------------------------------------------
# MARK ALL NOTIFICATIONS AS READ
# --------------------------------------------------

@app.route(
    "/notifications/mark-all-read",
    methods=["POST"]
)
def mark_all_notifications_read():

    if os.path.exists(NOTIFICATION_FILE):

        try:
            notification_data = pd.read_csv(
                NOTIFICATION_FILE
            )

            if not notification_data.empty:

                notification_data["is_read"] = True

                notification_data.to_csv(
                    NOTIFICATION_FILE,
                    index=False
                )

        except Exception as error:
            print("[WiSecure] Mark all notifications error:", error)

    return redirect(url_for("notifications"))


# --------------------------------------------------
# ALERT HISTORY PAGE
# --------------------------------------------------

@app.route("/alerts")
def alert_history():

    if os.path.exists(ALERT_FILE):

        try:
            history = pd.read_csv(ALERT_FILE)
            history = history.reindex(columns=ALERT_COLUMNS)

            if not history.empty:

                history = history.tail(
                    MAX_ALERT_HISTORY
                ).copy()

                history["hybrid_score"] = pd.to_numeric(
                    history["hybrid_score"],
                    errors="coerce"
                ).fillna(0)

                history = history.sort_values(
                    "alert_detected_at",
                    ascending=False
                )

            else:
                history = pd.DataFrame(columns=ALERT_COLUMNS)

        except Exception as error:
            print("[WiSecure] Alert history error:", error)
            history = pd.DataFrame(columns=ALERT_COLUMNS)

    else:
        history = pd.DataFrame(columns=ALERT_COLUMNS)

    total_alerts = len(history)

    stats = {
        "total": total_alerts,
        "high": int(
            (history["hybrid_risk"] == "HIGH").sum()
        ) if total_alerts else 0,
        "medium": int(
            (history["hybrid_risk"] == "MEDIUM").sum()
        ) if total_alerts else 0
    }

    records = (
        history.head(MAX_ALERT_PAGE_ROWS)
        .replace({np.nan: ""})
        .to_dict(orient="records")
    )

    return render_template(
        "alerts.html",
        alerts=records,
        stats=stats
    )


# --------------------------------------------------
# ADVANCED TRAFFIC ANALYTICS
# --------------------------------------------------

@app.route("/incidents")
def incidents():

    try:
        incident_data = correlate_security_events()

        incidents_list = incident_data.get("incidents", [])

        summary = {
            "total_incidents": incident_data.get("total_incidents", 0),
            "total_alerts": incident_data.get("total_alerts", 0),
            "high_incidents": incident_data.get("high_incidents", 0),
            "medium_incidents": incident_data.get("medium_incidents", 0),
            "correlated_alerts": incident_data.get("correlated_alerts", 0)
        }

        return render_template(
            "attack_timeline.html",
            incidents=incidents_list,
            summary=summary,
            error=incident_data.get("error")
        )

    except Exception as e:

        print("Incident correlation error:", str(e))

        summary = {
            "total_incidents": 0,
            "total_alerts": 0,
            "high_incidents": 0,
            "medium_incidents": 0,
            "correlated_alerts": 0
        }

        return render_template(
            "attack_timeline.html",
            incidents=[],
            summary=summary,
            error=str(e)
        )

@app.route("/analytics")
def analytics():

    flows, summary = process_flows()

    analytics_data = {
        "error": None,
        "total_flows": 0,
        "total_packets": 0,
        "total_bytes": 0,
        "average_flow_size": 0,
        "protocol_labels": [],
        "protocol_values": [],
        "source_labels": [],
        "source_values": [],
        "destination_labels": [],
        "destination_values": [],
        "port_labels": [],
        "port_values": [],
        "timeline_labels": [],
        "timeline_values": []
    }

    if flows.empty:

        analytics_data["error"] = summary.get(
            "error",
            "No eligible network flows available."
        )

        return render_template(
            "analytics.html",
            analytics=analytics_data
        )

    analytics_data["total_flows"] = int(len(flows))
    analytics_data["total_packets"] = int(
        flows["total_packets"].sum()
    )
    analytics_data["total_bytes"] = int(
        flows["total_bytes"].sum()
    )
    analytics_data["average_flow_size"] = round(
        float(flows["total_bytes"].mean()),
        2
    )

    protocol_counts = flows["protocol"].value_counts()

    analytics_data["protocol_labels"] = (
        protocol_counts.index.astype(str).tolist()
    )
    analytics_data["protocol_values"] = (
        protocol_counts.astype(int).tolist()
    )

    source_counts = (
        flows.groupby("source_ip")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )

    analytics_data["source_labels"] = (
        source_counts.index.astype(str).tolist()
    )
    analytics_data["source_values"] = (
        source_counts.astype(int).tolist()
    )

    destination_counts = (
        flows.groupby("destination_ip")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )

    analytics_data["destination_labels"] = (
        destination_counts.index.astype(str).tolist()
    )
    analytics_data["destination_values"] = (
        destination_counts.astype(int).tolist()
    )

    port_data = flows.copy()

    port_data["destination_port"] = pd.to_numeric(
        port_data["destination_port"],
        errors="coerce"
    )

    port_counts = (
        port_data.dropna(subset=["destination_port"])
        .groupby("destination_port")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )

    analytics_data["port_labels"] = [
        str(int(port)) for port in port_counts.index
    ]
    analytics_data["port_values"] = (
        port_counts.astype(int).tolist()
    )

    timeline_data = flows.dropna(
        subset=["first_seen_dt"]
    ).copy()

    if not timeline_data.empty:

        timeline_data["time_bucket"] = (
            timeline_data["first_seen_dt"].dt.floor("1min")
        )

        timeline_counts = (
            timeline_data.groupby("time_bucket")
            .size()
            .sort_index()
            .tail(20)
        )

        analytics_data["timeline_labels"] = [
            timestamp.strftime("%H:%M")
            for timestamp in timeline_counts.index
        ]

        analytics_data["timeline_values"] = (
            timeline_counts.astype(int).tolist()
        )

    return render_template(
        "analytics.html",
        analytics=analytics_data
    )


# --------------------------------------------------
# IP INVESTIGATION
# --------------------------------------------------

@app.route("/investigate", methods=["GET"])
def investigate_ip():

    searched_ip = request.args.get("ip", "").strip()

    if not searched_ip:
        network_info = get_network_info()
        searched_ip = network_info.get("ip_address", "")

        if searched_ip == "Unavailable":
            searched_ip = ""

    investigation = None
    error = None

    if not searched_ip:

        return render_template(
            "ip_investigation.html",
            searched_ip="",
            investigation=None,
            error=None
        )

    try:
        searched_ip = str(ipaddress.ip_address(searched_ip))

    except ValueError:

        error = (
            "Invalid IP address. Please enter a valid IPv4 or IPv6 address."
        )

        return render_template(
            "ip_investigation.html",
            searched_ip=request.args.get("ip", "").strip(),
            investigation=None,
            error=error
        )

    flows, summary = process_flows()

    if flows is None or flows.empty:

        error = summary.get(
            "error",
            "No flow records are currently available."
        )

        return render_template(
            "ip_investigation.html",
            searched_ip=searched_ip,
            investigation=None,
            error=error
        )

    required_columns = [
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "total_packets",
        "total_bytes",
        "model_prediction",
        "hybrid_risk",
        "hybrid_score",
        "detection_explanation"
    ]

    missing = [
        column for column in required_columns
        if column not in flows.columns
    ]

    if missing:

        error = (
            "Investigation cannot run because flow data is missing: "
            + ", ".join(missing)
        )

        return render_template(
            "ip_investigation.html",
            searched_ip=searched_ip,
            investigation=None,
            error=error
        )

    source_match = (
        flows["source_ip"].astype(str).str.strip()
        == searched_ip
    )

    destination_match = (
        flows["destination_ip"].astype(str).str.strip()
        == searched_ip
    )

    matched = flows[
        source_match | destination_match
    ].copy()

    if matched.empty:

        error = (
            "This IP address was not found in the latest flow records "
            "currently loaded by WiSecure."
        )

        return render_template(
            "ip_investigation.html",
            searched_ip=searched_ip,
            investigation=None,
            error=error
        )

    for column in [
        "total_packets",
        "total_bytes",
        "source_port",
        "destination_port",
        "hybrid_score"
    ]:
        matched[column] = pd.to_numeric(
            matched[column],
            errors="coerce"
        ).fillna(0)

    matched["hybrid_risk"] = (
        matched["hybrid_risk"].astype(str).str.upper()
    )

    matched["peer_ip"] = np.where(
        source_match.loc[matched.index],
        matched["destination_ip"].astype(str),
        matched["source_ip"].astype(str)
    )

    risk_counts = matched["hybrid_risk"].value_counts()

    high = int(risk_counts.get("HIGH", 0))
    medium = int(risk_counts.get("MEDIUM", 0))
    low = int(risk_counts.get("LOW", 0))
    info = int(risk_counts.get("INFO", 0))

    total_flows = len(matched)
    total_packets = int(matched["total_packets"].sum())
    total_bytes = int(matched["total_bytes"].sum())

    peer_data = (
        matched.groupby("peer_ip")
        .agg(
            flows=("peer_ip", "size"),
            packets=("total_packets", "sum"),
            data=("total_bytes", "sum")
        )
        .sort_values("flows", ascending=False)
        .head(15)
        .reset_index()
    )

    peers = [
        {
            "ip": str(row["peer_ip"]),
            "flows": int(row["flows"]),
            "packets": int(row["packets"]),
            "data_mb": round(
                float(row["data"]) / (1024 * 1024), 3
            )
        }
        for _, row in peer_data.iterrows()
    ]

    port_values = pd.concat([
        matched["source_port"],
        matched["destination_port"]
    ])

    port_counts = (
        port_values[port_values > 0]
        .astype(int)
        .value_counts()
        .head(15)
    )

    ports = [
        {"port": int(port), "flows": int(count)}
        for port, count in port_counts.items()
    ]

    matched["_sort_time"] = pd.to_datetime(
        matched["first_seen"],
        errors="coerce",
        utc=True
    )

    matched = matched.sort_values(
        "_sort_time",
        ascending=False,
        na_position="last"
    )

    flow_records = []

    for _, row in matched.head(100).iterrows():

        timestamp = row.get("first_seen", "Unavailable")

        if pd.notna(row.get("_sort_time")):
            timestamp = row["_sort_time"].strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )

        flow_records.append({
            "first_seen": str(timestamp),
            "protocol": str(row.get("protocol", "UNKNOWN")),
            "source_ip": str(row.get("source_ip", "")),
            "destination_ip": str(row.get("destination_ip", "")),
            "source_port": int(row["source_port"]),
            "destination_port": int(row["destination_port"]),
            "total_packets": int(row["total_packets"]),
            "total_bytes": int(row["total_bytes"]),
            "model_prediction": str(
                row.get("model_prediction", "N/A")
            ),
            "hybrid_risk": str(
                row.get("hybrid_risk", "INFO")
            ),
            "detection_explanation": str(
                row.get(
                    "detection_explanation",
                    "No explanation available"
                )
            )
        })

    related_alerts = []

    if os.path.exists(ALERT_FILE):

        try:
            alert_df = pd.read_csv(ALERT_FILE)

            if {
                "source_ip",
                "destination_ip"
            }.issubset(alert_df.columns):

                alert_match = (
                    alert_df["source_ip"].astype(str)
                    .str.strip().eq(searched_ip)
                    |
                    alert_df["destination_ip"].astype(str)
                    .str.strip().eq(searched_ip)
                )

                alert_df = alert_df[alert_match].copy()

                if "alert_detected_at" in alert_df.columns:
                    alert_df = alert_df.sort_values(
                        "alert_detected_at",
                        ascending=False
                    )

                for _, row in alert_df.head(100).iterrows():

                    related_alerts.append({
                        "alert_detected_at": str(
                            row.get(
                                "alert_detected_at",
                                "Unavailable"
                            )
                        ),
                        "protocol": str(
                            row.get("protocol", "UNKNOWN")
                        ),
                        "source_ip": str(row.get("source_ip", "")),
                        "destination_ip": str(
                            row.get("destination_ip", "")
                        ),
                        "source_port": str(
                            row.get("source_port", "")
                        ),
                        "destination_port": str(
                            row.get("destination_port", "")
                        ),
                        "hybrid_risk": str(
                            row.get("hybrid_risk", "INFO")
                        ).upper(),
                        "hybrid_score": str(
                            row.get("hybrid_score", "N/A")
                        ),
                        "detection_explanation": str(
                            row.get("detection_explanation", "")
                        )
                    })

        except Exception as exc:
            print(
                f"IP investigation alert history error: {exc}"
            )

    protocol_counts = (
        matched["protocol"].astype(str).str.upper().value_counts()
    )

    common_protocol = (
        str(protocol_counts.index[0])
        if not protocol_counts.empty
        else "Unknown"
    )

    most_common_peer = (
        peers[0]["ip"] if peers else "Unavailable"
    )

    summary_text = (
        f"WiSecure observed {total_flows} eligible flow records "
        f"involving {searched_ip}. The records contain "
        f"{total_packets} packets and "
        f"{round(total_bytes / (1024 * 1024), 3)} MB of traffic. "
        f"The most common protocol was {common_protocol}, and the most "
        f"frequent connected peer was {most_common_peer}. "
        f"Risk classification: {high} HIGH, {medium} MEDIUM, "
        f"{low} LOW and {info} INFO. "
        f"{len(related_alerts)} matching persistent alert records were found."
    )

    investigation = {
        "total_flows": total_flows,
        "total_packets": total_packets,
        "total_bytes_mb": round(
            total_bytes / (1024 * 1024), 3
        ),
        "unique_peers": int(matched["peer_ip"].nunique()),
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "peers": peers,
        "ports": ports,
        "flows": flow_records,
        "alerts": related_alerts,
        "summary": summary_text
    }

    return render_template(
        "ip_investigation.html",
        searched_ip=searched_ip,
        investigation=investigation,
        error=None
    )


# --------------------------------------------------
# THREAT INTELLIGENCE DASHBOARD
# --------------------------------------------------

@app.route("/threat-intel")
def threat_intel():

    data = {
        "total_flows": 0,
        "high": 0,
        "medium": 0,
        "alert_count": 0,
        "flagged_ips": [],
        "ports": [],
        "indicators": [],
        "alerts": []
    }

    flows, summary = process_flows()

    if flows is None or flows.empty:

        error = summary.get(
            "error",
            "No flow records are available for threat analysis."
        )

        return render_template(
            "threat_intel.html",
            data=data,
            error=error
        )

    required_columns = [
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "total_packets",
        "total_bytes",
        "protocol",
        "hybrid_risk",
        "detection_explanation"
    ]

    missing = [
        column for column in required_columns
        if column not in flows.columns
    ]

    if missing:

        error = (
            "Missing required flow columns: "
            + ", ".join(missing)
        )

        return render_template(
            "threat_intel.html",
            data=data,
            error=error
        )

    flows = flows.copy()

    for column in [
        "source_port",
        "destination_port",
        "total_packets",
        "total_bytes"
    ]:
        flows[column] = pd.to_numeric(
            flows[column],
            errors="coerce"
        ).fillna(0)

    flows["hybrid_risk"] = (
        flows["hybrid_risk"].astype(str).str.upper()
    )

    data["total_flows"] = int(len(flows))
    data["high"] = int(
        (flows["hybrid_risk"] == "HIGH").sum()
    )
    data["medium"] = int(
        (flows["hybrid_risk"] == "MEDIUM").sum()
    )

    elevated = flows[
        flows["hybrid_risk"].isin(["HIGH", "MEDIUM"])
    ].copy()

    # IP threat ranking

    endpoint_records = []

    for _, row in elevated.iterrows():

        risk = row["hybrid_risk"]

        for ip in [
            str(row["source_ip"]).strip(),
            str(row["destination_ip"]).strip()
        ]:

            if not ip or ip.lower() == "nan":
                continue

            endpoint_records.append({
                "ip": ip,
                "high": 1 if risk == "HIGH" else 0,
                "medium": 1 if risk == "MEDIUM" else 0,
                "packets": int(row["total_packets"]),
                "bytes": int(row["total_bytes"])
            })

    if endpoint_records:

        ip_df = pd.DataFrame(endpoint_records)

        ip_summary = (
            ip_df.groupby("ip")
            .agg(
                high=("high", "sum"),
                medium=("medium", "sum"),
                flows=("ip", "size"),
                packets=("packets", "sum"),
                bytes=("bytes", "sum")
            )
            .reset_index()
        )

        ip_summary["score"] = (
            ip_summary["high"] * 5
            + ip_summary["medium"] * 2
        )

        ip_summary = ip_summary.sort_values(
            ["score", "high", "medium", "flows"],
            ascending=False
        ).head(20)

        data["flagged_ips"] = [
            {
                "ip": str(row["ip"]),
                "score": int(row["score"]),
                "high": int(row["high"]),
                "medium": int(row["medium"]),
                "flows": int(row["flows"]),
                "packets": int(row["packets"]),
                "data_mb": round(
                    float(row["bytes"]) / (1024 * 1024), 3
                )
            }
            for _, row in ip_summary.iterrows()
        ]

    # Elevated-risk port analysis

    port_records = []

    for _, row in elevated.iterrows():

        risk = row["hybrid_risk"]

        for port in [
            row["source_port"],
            row["destination_port"]
        ]:

            port = int(port)

            if port <= 0 or port > 65535:
                continue

            port_records.append({
                "port": port,
                "high": 1 if risk == "HIGH" else 0,
                "medium": 1 if risk == "MEDIUM" else 0
            })

    if port_records:

        port_df = pd.DataFrame(port_records)

        port_summary = (
            port_df.groupby("port")
            .agg(
                high=("high", "sum"),
                medium=("medium", "sum")
            )
            .reset_index()
        )

        port_summary["total"] = (
            port_summary["high"] + port_summary["medium"]
        )

        port_summary = port_summary.sort_values(
            ["total", "high"],
            ascending=False
        ).head(20)

        data["ports"] = [
            {
                "port": int(row["port"]),
                "high": int(row["high"]),
                "medium": int(row["medium"]),
                "total": int(row["total"])
            }
            for _, row in port_summary.iterrows()
        ]

    # Behavioral indicators

    explanations = (
        elevated["detection_explanation"]
        .fillna("Unspecified detection finding")
        .astype(str)
        .str.strip()
    )

    explanations = explanations[explanations != ""]

    indicator_counts = explanations.value_counts().head(15)

    data["indicators"] = [
        {
            "indicator": str(indicator),
            "count": int(count)
        }
        for indicator, count in indicator_counts.items()
    ]

    # Persistent alert correlation

    if os.path.exists(ALERT_FILE):

        try:
            alert_df = pd.read_csv(ALERT_FILE)

            if "hybrid_risk" in alert_df.columns:

                alert_df["hybrid_risk"] = (
                    alert_df["hybrid_risk"]
                    .astype(str)
                    .str.upper()
                )

                alert_df = alert_df[
                    alert_df["hybrid_risk"].isin(
                        ["HIGH", "MEDIUM"]
                    )
                ].copy()

                data["alert_count"] = int(len(alert_df))

                if "alert_detected_at" in alert_df.columns:
                    alert_df = alert_df.sort_values(
                        "alert_detected_at",
                        ascending=False
                    )

                for _, row in alert_df.head(20).iterrows():

                    data["alerts"].append({
                        "time": str(
                            row.get(
                                "alert_detected_at",
                                "Unavailable"
                            )
                        ),
                        "source_ip": str(
                            row.get("source_ip", "")
                        ),
                        "destination_ip": str(
                            row.get("destination_ip", "")
                        ),
                        "protocol": str(
                            row.get("protocol", "UNKNOWN")
                        ),
                        "risk": str(
                            row.get("hybrid_risk", "INFO")
                        ),
                        "score": str(
                            row.get("hybrid_score", "N/A")
                        )
                    })

        except Exception as exc:
            print(
                f"Threat intelligence alert error: {exc}"
            )

    return render_template(
        "threat_intel.html",
        data=data,
        error=None
    )


# --------------------------------------------------
# AUTOMATED INCIDENT REPORT PDF GENERATOR
# --------------------------------------------------

def create_incident_pdf(report_data, pdf_path):

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["BodyText"]

    title_style.alignment = TA_CENTER

    document = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    elements = []

    elements.append(
        Paragraph("WiSecure 2.0", title_style)
    )

    elements.append(
        Paragraph(
            "Automated Network Security Incident Report",
            styles["Heading2"]
        )
    )

    elements.append(Spacer(1, 12))

    metadata = [
        ["Report ID", report_data["report_id"]],
        ["Generated At", report_data["generated_at"]],
        ["Investigated IP", report_data["investigated_ip"]],
        ["Total Associated Flows", str(report_data["total_flows"])]
    ]

    metadata_table = Table(
        metadata,
        colWidths=[55 * mm, 115 * mm]
    )

    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eaf0f8")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dce5")),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(metadata_table)
    elements.append(Spacer(1, 18))

    elements.append(
        Paragraph("1. Risk Classification Summary", heading_style)
    )

    risk_table = [
        ["Risk Level", "Associated Flows"],
        ["HIGH", str(report_data["high"])],
        ["MEDIUM", str(report_data["medium"])],
        ["LOW", str(report_data["low"])],
        ["INFO", str(report_data["info"])]
    ]

    risk_table_obj = Table(
        risk_table,
        colWidths=[85 * mm, 85 * mm]
    )

    risk_table_obj.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dce5")),
        ("PADDING", (0, 0), (-1, -1), 8)
    ]))

    elements.append(risk_table_obj)
    elements.append(Spacer(1, 15))

    elements.append(
        Paragraph("2. Network Traffic Statistics", heading_style)
    )

    traffic_table = [
        ["Metric", "Value"],
        ["Total Packets", str(report_data["total_packets"])],
        ["Total Traffic (MB)", str(report_data["total_mb"])],
        ["Unique Peer IPs", str(report_data["unique_peers"])],
        ["Most Common Protocol", report_data["common_protocol"]]
    ]

    traffic_table_obj = Table(
        traffic_table,
        colWidths=[85 * mm, 85 * mm]
    )

    traffic_table_obj.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dce5")),
        ("PADDING", (0, 0), (-1, -1), 8)
    ]))

    elements.append(traffic_table_obj)
    elements.append(Spacer(1, 15))

    elements.append(
        Paragraph("3. Investigation Summary", heading_style)
    )

    elements.append(
        Paragraph(
            escape(report_data["summary"]),
            normal_style
        )
    )

    elements.append(Spacer(1, 15))

    elements.append(
        Paragraph("4. Connected Peer IP Addresses", heading_style)
    )

    peer_table = [
        ["Peer IP", "Flows", "Packets", "Traffic (MB)"]
    ]

    for peer in report_data["peers"]:
        peer_table.append([
            peer["ip"],
            str(peer["flows"]),
            str(peer["packets"]),
            str(peer["data_mb"])
        ])

    if len(peer_table) == 1:
        peer_table.append(["No peer records", "-", "-", "-"])

    peer_table_obj = Table(
        peer_table,
        colWidths=[65 * mm, 30 * mm, 35 * mm, 40 * mm],
        repeatRows=1
    )

    peer_table_obj.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dce5")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 8)
    ]))

    elements.append(peer_table_obj)
    elements.append(Spacer(1, 15))

    elements.append(
        Paragraph("5. Detection Findings", heading_style)
    )

    findings = sorted(set(
        str(flow.get("detection_explanation", ""))
        for flow in report_data["flows"]
        if flow.get("detection_explanation")
    ))

    if findings:

        for finding in findings:
            elements.append(
                Paragraph(
                    "- " + escape(finding),
                    normal_style
                )
            )
            elements.append(Spacer(1, 4))

    else:
        elements.append(
            Paragraph(
                "No detection findings were recorded.",
                normal_style
            )
        )

    elements.append(Spacer(1, 15))

    elements.append(
        Paragraph("6. Related Persistent Alerts", heading_style)
    )

    alert_table = [
        ["Detected At", "Protocol", "Risk", "Score"]
    ]

    for alert in report_data["alerts"][:30]:

        alert_table.append([
            str(alert.get("alert_detected_at", ""))[:25],
            str(alert.get("protocol", "")),
            str(alert.get("hybrid_risk", "")),
            str(alert.get("hybrid_score", ""))
        ])

    if len(alert_table) == 1:
        alert_table.append([
            "No matching alerts", "-", "-", "-"
        ])

    alert_table_obj = Table(
        alert_table,
        colWidths=[65 * mm, 30 * mm, 35 * mm, 40 * mm],
        repeatRows=1
    )

    alert_table_obj.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dce5")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 8)
    ]))

    elements.append(alert_table_obj)
    elements.append(Spacer(1, 18))

    elements.append(
        Paragraph("7. Methodology and Limitations", heading_style)
    )

    limitation_text = (
        "This report uses WiSecure's existing Isolation Forest anomaly "
        "detection, behavioral rules and hybrid risk classification. "
        "HIGH, MEDIUM, LOW and INFO are system classifications, not "
        "confirmed threat verdicts. An anomaly does not independently "
        "prove malicious activity. The report covers eligible flow records "
        "from the latest records processed by WiSecure and matching entries "
        "in its persistent alert history."
    )

    elements.append(
        Paragraph(
            escape(limitation_text),
            normal_style
        )
    )

    document.build(elements)


# --------------------------------------------------
# REPORT GENERATOR PAGE
# --------------------------------------------------

@app.route("/reports", methods=["GET"])
def report_generator():

    reports = []

    if os.path.exists(REPORT_HISTORY_FILE):

        try:
            report_df = pd.read_csv(REPORT_HISTORY_FILE)

            if not report_df.empty:

                report_df = report_df.sort_values(
                    "generated_at",
                    ascending=False
                )

                reports = (
                    report_df.head(100)
                    .fillna("")
                    .to_dict(orient="records")
                )

        except Exception as error:
            print("[WiSecure] Report history error:", error)

    return render_template(
        "report_generator.html",
        reports=reports,
        error=None,
        success=request.args.get("success")
    )


# --------------------------------------------------
# GENERATE INCIDENT REPORT
# --------------------------------------------------

@app.route("/reports/generate", methods=["POST"])
def generate_incident_report():

    searched_ip = request.form.get("ip", "").strip()

    try:
        searched_ip = str(ipaddress.ip_address(searched_ip))

    except ValueError:

        return render_template(
            "report_generator.html",
            reports=[],
            error="Please enter a valid IPv4 or IPv6 address.",
            success=None
        )

    flows, summary = process_flows()

    if flows is None or flows.empty:

        return render_template(
            "report_generator.html",
            reports=[],
            error=summary.get(
                "error",
                "No eligible network flows available."
            ),
            success=None
        )

    matched = flows[
        (
            flows["source_ip"].astype(str).str.strip()
            == searched_ip
        )
        |
        (
            flows["destination_ip"].astype(str).str.strip()
            == searched_ip
        )
    ].copy()

    if matched.empty:

        return render_template(
            "report_generator.html",
            reports=[],
            error="No eligible flow records were found for this IP.",
            success=None
        )

    for column in [
        "total_packets",
        "total_bytes",
        "source_port",
        "destination_port",
        "hybrid_score"
    ]:
        matched[column] = pd.to_numeric(
            matched[column],
            errors="coerce"
        ).fillna(0)

    matched["hybrid_risk"] = (
        matched["hybrid_risk"].astype(str).str.upper()
    )

    risk_counts = matched["hybrid_risk"].value_counts()

    high = int(risk_counts.get("HIGH", 0))
    medium = int(risk_counts.get("MEDIUM", 0))
    low = int(risk_counts.get("LOW", 0))
    info = int(risk_counts.get("INFO", 0))

    total_flows = len(matched)
    total_packets = int(matched["total_packets"].sum())
    total_bytes = int(matched["total_bytes"].sum())

    matched["peer_ip"] = np.where(
        matched["source_ip"].astype(str).str.strip()
        == searched_ip,
        matched["destination_ip"].astype(str),
        matched["source_ip"].astype(str)
    )

    peer_df = (
        matched.groupby("peer_ip")
        .agg(
            flows=("peer_ip", "size"),
            packets=("total_packets", "sum"),
            bytes=("total_bytes", "sum")
        )
        .sort_values("flows", ascending=False)
        .head(30)
        .reset_index()
    )

    peers = [
        {
            "ip": str(row["peer_ip"]),
            "flows": int(row["flows"]),
            "packets": int(row["packets"]),
            "data_mb": round(
                float(row["bytes"]) / (1024 * 1024), 3
            )
        }
        for _, row in peer_df.iterrows()
    ]

    protocol_counts = (
        matched["protocol"].astype(str).value_counts()
    )

    common_protocol = (
        str(protocol_counts.index[0])
        if not protocol_counts.empty
        else "Unknown"
    )

    related_alerts = []

    if os.path.exists(ALERT_FILE):

        try:
            alert_df = pd.read_csv(ALERT_FILE)

            if {
                "source_ip",
                "destination_ip"
            }.issubset(alert_df.columns):

                alert_match = (
                    alert_df["source_ip"].astype(str)
                    .str.strip().eq(searched_ip)
                    |
                    alert_df["destination_ip"].astype(str)
                    .str.strip().eq(searched_ip)
                )

                alert_df = alert_df[alert_match].copy()

                if "alert_detected_at" in alert_df.columns:
                    alert_df = alert_df.sort_values(
                        "alert_detected_at",
                        ascending=False
                    )

                related_alerts = (
                    alert_df.fillna("")
                    .head(100)
                    .to_dict(orient="records")
                )

        except Exception as error:
            print(
                "[WiSecure] Report alert correlation error:",
                error
            )

    matched = matched.sort_values(
        "first_seen_dt",
        ascending=False,
        na_position="last"
    )

    export_columns = [
        "first_seen",
        "protocol",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "total_packets",
        "total_bytes",
        "model_prediction",
        "anomaly_score",
        "hybrid_score",
        "hybrid_risk",
        "behavioral_reasons",
        "detection_explanation"
    ]

    export_columns = [
        column for column in export_columns
        if column in matched.columns
    ]

    export_df = matched[export_columns].copy()

    report_id = uuid.uuid4().hex[:12].upper()

    generated_at = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    pdf_filename = f"incident_{report_id}.pdf"
    csv_filename = f"incident_{report_id}.csv"

    pdf_path = os.path.join(REPORT_DIR, pdf_filename)
    csv_path = os.path.join(REPORT_DIR, csv_filename)

    try:
        export_df.to_csv(csv_path, index=False)

        summary_text = (
            f"WiSecure observed {total_flows} eligible flows involving "
            f"{searched_ip}. These flows contained {total_packets} packets "
            f"and {round(total_bytes / (1024 * 1024), 3)} MB of traffic. "
            f"The most common protocol was {common_protocol}. "
            f"Risk breakdown: {high} HIGH, {medium} MEDIUM, "
            f"{low} LOW and {info} INFO. "
            f"{len(related_alerts)} matching persistent alert records "
            f"were found."
        )

        report_data = {
            "report_id": report_id,
            "generated_at": generated_at,
            "investigated_ip": searched_ip,
            "total_flows": total_flows,
            "total_packets": total_packets,
            "total_mb": round(
                total_bytes / (1024 * 1024), 3
            ),
            "unique_peers": int(matched["peer_ip"].nunique()),
            "common_protocol": common_protocol,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "peers": peers,
            "alerts": related_alerts,
            "flows": (
                export_df.fillna("")
                .to_dict(orient="records")
            ),
            "summary": summary_text
        }

        create_incident_pdf(report_data, pdf_path)

    except Exception as error:

        print("[WiSecure] Report generation error:", error)

        for path in [pdf_path, csv_path]:
            if os.path.exists(path):
                os.remove(path)

        return render_template(
            "report_generator.html",
            reports=[],
            error=f"Could not generate report: {error}",
            success=None
        )

    history_record = {
        "report_id": report_id,
        "generated_at": generated_at,
        "investigated_ip": searched_ip,
        "total_flows": total_flows,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "pdf_file": pdf_filename,
        "csv_file": csv_filename
    }

    try:

        if os.path.exists(REPORT_HISTORY_FILE):
            history_df = pd.read_csv(REPORT_HISTORY_FILE)

        else:
            history_df = pd.DataFrame(
                columns=REPORT_HISTORY_COLUMNS
            )

        history_df = pd.concat(
            [
                history_df,
                pd.DataFrame([history_record])
            ],
            ignore_index=True
        )

        history_df = history_df.reindex(
            columns=REPORT_HISTORY_COLUMNS
        )

        history_df.to_csv(
            REPORT_HISTORY_FILE,
            index=False
        )

    except Exception as error:
        print("[WiSecure] Report history save error:", error)

    return redirect(
        url_for(
            "report_generator",
            success=report_id
        )
    )


# --------------------------------------------------
# DOWNLOAD PDF REPORT
# --------------------------------------------------

@app.route("/reports/<report_id>/pdf")
def download_report_pdf(report_id):

    if not report_id.isalnum():
        return "Invalid report ID", 400

    filename = f"incident_{report_id}.pdf"
    file_path = os.path.join(REPORT_DIR, filename)

    if not os.path.isfile(file_path):
        return "Report not found", 404

    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename
    )


@app.route("/api/notifications/latest")
def latest_notification_api():

    if not os.path.exists(NOTIFICATION_FILE):
        return jsonify({"notifications": []})

    try:
        data = pd.read_csv(NOTIFICATION_FILE)

        if data.empty:
            return jsonify({"notifications": []})

        data = data.reindex(columns=NOTIFICATION_COLUMNS)

        data["is_read"] = (
            data["is_read"]
            .astype(str)
            .str.strip()
            .str.lower()
            .isin(["true", "1", "yes"])
        )

        unread = data[data["is_read"] == False].copy()

        if unread.empty:
            return jsonify({"notifications": []})

        unread = unread.sort_values(
            "created_at",
            ascending=False
        )

        latest = unread.iloc[0]

        return jsonify({
            "notifications": [{
                "notification_id": str(latest["notification_id"]),
                "risk_level": str(latest["risk_level"]),
                "source_ip": str(latest["source_ip"]),
                "destination_ip": str(latest["destination_ip"]),
                "reason": str(latest["reason"])
            }]
        })

    except Exception as error:
        print("[WiSecure] Notification API error:", error)
        return jsonify({"notifications": []}), 500

# --------------------------------------------------
# DOWNLOAD CSV REPORT
# --------------------------------------------------

@app.route("/reports/<report_id>/csv")
def download_report_csv(report_id):

    if not report_id.isalnum():
        return "Invalid report ID", 400

    filename = f"incident_{report_id}.csv"
    file_path = os.path.join(REPORT_DIR, filename)

    if not os.path.isfile(file_path):
        return "Report not found", 404

    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename
    )


# --------------------------------------------------
# APPLICATION START
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
