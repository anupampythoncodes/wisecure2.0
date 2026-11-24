
import os
import hashlib
import pandas as pd


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ALERT_FILE = os.path.join(
    BASE_DIR,
    "wisecure_alert_history.csv"
)

CORRELATION_WINDOW_MINUTES = 10
PORT_SCAN_WINDOW_SECONDS = 60
PORT_SCAN_THRESHOLD = 15
DESTINATION_SPREAD_THRESHOLD = 5

MAX_ALERT_RECORDS = 5000


def load_alert_history():

    if not os.path.exists(ALERT_FILE):
        return pd.DataFrame()

    try:
        df = pd.read_csv(ALERT_FILE)

        if df.empty:
            return pd.DataFrame()

        required_columns = [
            "alert_id",
            "alert_detected_at",
            "protocol",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "hybrid_risk",
            "hybrid_score",
            "detection_explanation"
        ]

        missing = [
            col for col in required_columns
            if col not in df.columns
        ]

        if missing:
            print(
                "[WiSecure Correlation] Missing columns:",
                missing
            )
            return pd.DataFrame()

        df = df.tail(MAX_ALERT_RECORDS).copy()

        df = df.drop_duplicates(
            subset=["alert_id"],
            keep="last"
        )

        df["source_ip"] = (
            df["source_ip"].fillna("").astype(str).str.strip()
        )

        df["destination_ip"] = (
            df["destination_ip"].fillna("").astype(str).str.strip()
        )

        df["hybrid_risk"] = (
            df["hybrid_risk"].fillna("MEDIUM")
            .astype(str)
            .str.upper()
        )

        df["destination_port"] = pd.to_numeric(
            df["destination_port"],
            errors="coerce"
        )

        df["hybrid_score"] = pd.to_numeric(
            df["hybrid_score"],
            errors="coerce"
        ).fillna(0)

        df["event_time"] = pd.to_datetime(
            df["alert_detected_at"],
            errors="coerce",
            utc=True
        )

        df = df.dropna(subset=["event_time"])

        df = df[
            df["source_ip"].ne("")
            & df["source_ip"].ne("nan")
        ]

        return df.sort_values("event_time")

    except Exception as error:

        print(
            "[WiSecure Correlation] Read error:",
            error
        )

        return pd.DataFrame()


def detect_port_scanning(group):

    group = group.sort_values("event_time")

    records = group.to_dict(orient="records")

    for index, current in enumerate(records):

        start_time = current["event_time"]

        end_time = (
            start_time
            + pd.Timedelta(seconds=PORT_SCAN_WINDOW_SECONDS)
        )

        window = [
            row for row in records[index:]
            if start_time <= row["event_time"] <= end_time
        ]

        ports = set()

        for row in window:

            try:
                port = int(row["destination_port"])

                if 1 <= port <= 65535:
                    ports.add(port)

            except (TypeError, ValueError):
                continue

        if len(ports) >= PORT_SCAN_THRESHOLD:
            return True

    return False


def analyze_incident(group, source_ip):

    group = group.sort_values("event_time")

    alert_ids = sorted(
        group["alert_id"].astype(str).tolist()
    )

    first_event = group.iloc[0]["event_time"]
    last_event = group.iloc[-1]["event_time"]

    high_count = int(
        (group["hybrid_risk"] == "HIGH").sum()
    )

    medium_count = int(
        (group["hybrid_risk"] == "MEDIUM").sum()
    )

    destination_count = int(
        group["destination_ip"]
        .replace("", pd.NA)
        .dropna()
        .nunique()
    )

    unique_ports = set()

    for port in group["destination_port"].dropna():

        try:
            port = int(port)

            if 1 <= port <= 65535:
                unique_ports.add(port)

        except (TypeError, ValueError):
            continue

    indicators = []

    if detect_port_scanning(group):
        indicators.append("POSSIBLE_PORT_SCAN")

    if destination_count >= DESTINATION_SPREAD_THRESHOLD:
        indicators.append("MULTIPLE_DESTINATIONS")

    if len(group) >= 3:
        indicators.append("REPEATED_SOURCE_ACTIVITY")

    if high_count >= 2:
        indicators.append("REPEATED_HIGH_RISK_ALERTS")

    if not indicators:
        indicators.append("CORRELATED_ALERT_ACTIVITY")

    severity = (
        "HIGH" if high_count > 0 else "MEDIUM"
    )

    fingerprint = (
        source_ip + "|" + "|".join(alert_ids)
    )

    incident_id = hashlib.sha256(
        fingerprint.encode("utf-8")
    ).hexdigest()[:16].upper()

    events = []

    for _, row in group.iterrows():

        events.append({
            "alert_id": str(row["alert_id"]),
            "timestamp": row["event_time"].strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            "protocol": str(row["protocol"]),
            "source_ip": source_ip,
            "destination_ip": str(row["destination_ip"]),
            "source_port": str(row["source_port"]),
            "destination_port": str(row["destination_port"]),
            "risk": str(row["hybrid_risk"]),
            "score": int(row["hybrid_score"]),
            "explanation": str(
                row["detection_explanation"]
            )
        })

    return {
        "incident_id": incident_id,
        "source_ip": source_ip,
        "started_at": first_event.strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        ),
        "last_seen": last_event.strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        ),
        "alert_count": int(len(group)),
        "high_count": high_count,
        "medium_count": medium_count,
        "destination_count": destination_count,
        "unique_destination_ports": len(unique_ports),
        "severity": severity,
        "indicators": indicators,
        "events": events
    }


def correlate_security_events():

    df = load_alert_history()

    if df.empty:

        return {
            "incidents": [],
            "total_incidents": 0,
            "total_alerts": 0,
            "high_incidents": 0,
            "medium_incidents": 0,
            "correlated_alerts": 0,
            "error": None
        }

    incidents = []

    window = pd.Timedelta(
        minutes=CORRELATION_WINDOW_MINUTES
    )

    # Group alerts by source IP.
    for source_ip, source_group in df.groupby("source_ip"):

        source_group = source_group.sort_values(
            "event_time"
        )

        current_group = []
        previous_time = None

        # Separate incidents when the time gap exceeds 10 minutes.
        for _, row in source_group.iterrows():

            current_time = row["event_time"]

            if (
                previous_time is not None
                and current_time - previous_time > window
            ):

                if current_group:

                    incident = analyze_incident(
                        pd.DataFrame(current_group),
                        source_ip
                    )

                    incidents.append(incident)

                current_group = []

            current_group.append(row.to_dict())
            previous_time = current_time

        if current_group:

            incident = analyze_incident(
                pd.DataFrame(current_group),
                source_ip
            )

            incidents.append(incident)

    incidents.sort(
        key=lambda item: item["last_seen"],
        reverse=True
    )

    high_incidents = sum(
        incident["severity"] == "HIGH"
        for incident in incidents
    )

    medium_incidents = sum(
        incident["severity"] == "MEDIUM"
        for incident in incidents
    )

    correlated_alerts = sum(
        incident["alert_count"]
        for incident in incidents
    )

    return {
        "incidents": incidents,
        "total_incidents": len(incidents),
        "total_alerts": len(df),
        "high_incidents": high_incidents,
        "medium_incidents": medium_incidents,
        "correlated_alerts": correlated_alerts,
        "error": None
    }
