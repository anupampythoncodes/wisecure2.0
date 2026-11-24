
import os
import csv
import time
import threading

from datetime import datetime
from collections import deque

from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from interface_manager import get_active_npcap_interface


# ==========================================
# CONFIGURATION
# ==========================================

IDLE_TIMEOUT = 30
MAX_COMPLETED_FLOWS = 1000
STATUS_INTERVAL = 10

EXPORT_FILE = "persistent_flow_records_v2.csv"

stop_event = threading.Event()
flow_lock = threading.RLock()

active_flows = {}
completed_flows = deque(maxlen=MAX_COMPLETED_FLOWS)

total_packets_captured = 0
total_flows_created = 0


# ==========================================
# CSV SCHEMA
# ==========================================

CSV_FIELDS = [
    "protocol",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "first_seen",
    "last_seen",
    "flow_duration_us",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "total_packets",
    "total_bytes",
    "packet_length_mean",
    "flow_packet_rate",
    "initiator_detected",
    "direction_method",
    "flow_status",
    "close_reason"
]


# ==========================================
# PACKET EXTRACTION
# ==========================================

def extract_packet_info(packet):

    if packet.haslayer(IP):
        network = packet[IP]

    elif packet.haslayer(IPv6):
        network = packet[IPv6]

    else:
        return None

    if packet.haslayer(TCP):

        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        flags = int(packet[TCP].flags)

    elif packet.haslayer(UDP):

        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        flags = 0

    else:

        protocol = "OTHER"
        source_port = 0
        destination_port = 0
        flags = 0

    return {
        "protocol": protocol,
        "source": (network.src, source_port),
        "destination": (network.dst, destination_port),
        "packet_size": len(network),
        "timestamp": float(packet.time),
        "flags": flags
    }


# ==========================================
# FLOW IDENTIFICATION
# ==========================================

def create_flow_key(protocol, source, destination):

    endpoints = sorted([source, destination])

    return (
        protocol,
        endpoints[0],
        endpoints[1]
    )


# ==========================================
# CREATE NEW FLOW
# ==========================================

def create_new_flow(info):

    global total_flows_created

    total_flows_created += 1

    return {
        "protocol": info["protocol"],

        "source": info["source"],
        "destination": info["destination"],

        "first_seen": info["timestamp"],
        "last_seen": info["timestamp"],

        "total_fwd_packets": 0,
        "total_bwd_packets": 0,

        "total_fwd_bytes": 0,
        "total_bwd_bytes": 0,

        "total_packets": 0,
        "total_bytes": 0,

        "initiator_detected": False,
        "direction_method": "first_observed",

        "fin_from_source": False,
        "fin_from_destination": False,

        "flow_status": "ACTIVE",
        "close_reason": None
    }


# ==========================================
# TCP INITIATOR DETECTION
# ==========================================

def update_direction(flow, info):

    if info["protocol"] != "TCP":
        return

    if flow["initiator_detected"]:
        return

    flags = info["flags"]

    is_initial_syn = (
        bool(flags & 0x02)
        and not bool(flags & 0x10)
    )

    if not is_initial_syn:
        return

    # SYN packet identifies the TCP initiator.

    if info["source"] != flow["source"]:

        flow["total_fwd_packets"], flow["total_bwd_packets"] = (
            flow["total_bwd_packets"],
            flow["total_fwd_packets"]
        )

        flow["total_fwd_bytes"], flow["total_bwd_bytes"] = (
            flow["total_bwd_bytes"],
            flow["total_fwd_bytes"]
        )

        flow["fin_from_source"], flow["fin_from_destination"] = (
            flow["fin_from_destination"],
            flow["fin_from_source"]
        )

        flow["source"] = info["source"]
        flow["destination"] = info["destination"]

    flow["initiator_detected"] = True
    flow["direction_method"] = "tcp_syn"


# ==========================================
# UPDATE FLOW
# ==========================================

def update_flow(flow, info):

    timestamp = info["timestamp"]
    source = info["source"]
    packet_size = info["packet_size"]

    flow["first_seen"] = min(
        flow["first_seen"],
        timestamp
    )

    flow["last_seen"] = max(
        flow["last_seen"],
        timestamp
    )

    if source == flow["source"]:

        flow["total_fwd_packets"] += 1
        flow["total_fwd_bytes"] += packet_size

    else:

        flow["total_bwd_packets"] += 1
        flow["total_bwd_bytes"] += packet_size

    flow["total_packets"] += 1
    flow["total_bytes"] += packet_size


# ==========================================
# TIMESTAMP FORMATTING
# ==========================================

def format_timestamp(timestamp):

    return datetime.fromtimestamp(
        timestamp
    ).astimezone().isoformat(
        timespec="microseconds"
    )


# ==========================================
# GENERATE FLOW RECORD
# ==========================================

def generate_flow_record(flow):

    total_packets = flow["total_packets"]
    total_bytes = flow["total_bytes"]

    # Calculate duration once and use the
    # rounded microsecond value everywhere.

    duration = max(
        0,
        flow["last_seen"] - flow["first_seen"]
    )

    duration_us = round(
        duration * 1_000_000
    )

    duration_seconds = duration_us / 1_000_000

    packet_length_mean = (
        total_bytes / total_packets
        if total_packets > 0 else 0
    )

    packet_rate = (
        total_packets / duration_seconds
        if duration_seconds > 0 else 0
    )

    return {
        "protocol": flow["protocol"],

        "source_ip": flow["source"][0],
        "destination_ip": flow["destination"][0],

        "source_port": flow["source"][1],
        "destination_port": flow["destination"][1],

        "first_seen": format_timestamp(
            flow["first_seen"]
        ),

        "last_seen": format_timestamp(
            flow["last_seen"]
        ),

        "flow_duration_us": duration_us,

        "total_fwd_packets": flow["total_fwd_packets"],
        "total_bwd_packets": flow["total_bwd_packets"],

        "total_fwd_bytes": flow["total_fwd_bytes"],
        "total_bwd_bytes": flow["total_bwd_bytes"],

        "total_packets": total_packets,
        "total_bytes": total_bytes,

        "packet_length_mean": round(
            packet_length_mean, 2
        ),

        "flow_packet_rate": round(
            packet_rate, 2
        ),

        "initiator_detected": flow["initiator_detected"],
        "direction_method": flow["direction_method"],

        "flow_status": flow["flow_status"],
        "close_reason": flow["close_reason"]
    }


# ==========================================
# SAVE COMPLETED FLOW
# ==========================================

def save_completed_flow(flow):

    record = generate_flow_record(flow)

    file_exists = (
        os.path.exists(EXPORT_FILE)
        and os.path.getsize(EXPORT_FILE) > 0
    )

    if file_exists:

        with open(
            EXPORT_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as existing_file:

            existing_header = next(
                csv.reader(existing_file),
                []
            )

        if existing_header != CSV_FIELDS:

            raise RuntimeError(
                "CSV schema mismatch. "
                "Use a separate export filename."
            )

    with open(
        EXPORT_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=CSV_FIELDS
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(record)

    completed_flows.append(record)


# ==========================================
# CLOSE FLOW
# ==========================================

def close_flow(flow_key, reason):

    # Called while holding flow_lock.

    flow = active_flows.pop(flow_key, None)

    if flow is None:
        return

    if reason == "MONITOR_STOPPED":
        flow["flow_status"] = "PARTIAL"
    else:
        flow["flow_status"] = "COMPLETED"

    flow["close_reason"] = reason

    try:

        save_completed_flow(flow)

    except Exception as error:

        print("\nCSV export error:", error)

        completed_flows.append(
            generate_flow_record(flow)
        )


# ==========================================
# TCP TERMINATION
# ==========================================

def process_tcp_termination(flow_key, flow, info):

    flags = info["flags"]

    # TCP Reset

    if flags & 0x04:

        close_flow(
            flow_key,
            "TCP_RST"
        )

        return

    # TCP Finish

    if flags & 0x01:

        if info["source"] == flow["source"]:
            flow["fin_from_source"] = True

        else:
            flow["fin_from_destination"] = True

        if (
            flow["fin_from_source"]
            and flow["fin_from_destination"]
        ):

            close_flow(
                flow_key,
                "TCP_FIN_BOTH_DIRECTIONS"
            )


# ==========================================
# PACKET HANDLER
# ==========================================

def packet_handler(packet):

    global total_packets_captured

    if stop_event.is_set():
        return

    info = extract_packet_info(packet)

    if info is None:
        return

    with flow_lock:

        if stop_event.is_set():
            return

        total_packets_captured += 1

        flow_key = create_flow_key(
            info["protocol"],
            info["source"],
            info["destination"]
        )

        if flow_key not in active_flows:

            active_flows[flow_key] = create_new_flow(info)

        flow = active_flows[flow_key]

        update_direction(flow, info)

        update_flow(flow, info)

        if info["protocol"] == "TCP":

            process_tcp_termination(
                flow_key,
                flow,
                info
            )


# ==========================================
# IDLE TIMEOUT
# ==========================================

def expire_idle_flows():

    current_time = time.time()

    with flow_lock:

        expired_keys = [
            key
            for key, flow in active_flows.items()
            if current_time - flow["last_seen"] >= IDLE_TIMEOUT
        ]

        for key in expired_keys:

            close_flow(
                key,
                "IDLE_TIMEOUT"
            )


# ==========================================
# LIVE STATUS
# ==========================================

def print_live_status():

    with flow_lock:

        tcp_active = sum(
            flow["protocol"] == "TCP"
            for flow in active_flows.values()
        )

        udp_active = sum(
            flow["protocol"] == "UDP"
            for flow in active_flows.values()
        )

        other_active = sum(
            flow["protocol"] == "OTHER"
            for flow in active_flows.values()
        )

        print("\n===== WiSecure Live Flow Status =====")

        print(
            "Total packets captured:",
            total_packets_captured
        )

        print(
            "Total flows created:",
            total_flows_created
        )

        print(
            "Active flows:",
            len(active_flows)
        )

        print(
            "Completed flows:",
            len(completed_flows)
        )

        print("Active TCP flows:", tcp_active)
        print("Active UDP flows:", udp_active)
        print("Active other flows:", other_active)


# ==========================================
# GRACEFUL SHUTDOWN
# ==========================================

def shutdown_tracker(sniffer):

    print("\nStopping WiSecure flow tracker...")

    stop_event.set()

    try:

        if sniffer and sniffer.running:
            sniffer.stop()

    except Exception as error:

        print(
            "Capture shutdown warning:",
            error
        )

    with flow_lock:

        remaining_keys = list(active_flows.keys())

        for flow_key in remaining_keys:

            close_flow(
                flow_key,
                "MONITOR_STOPPED"
            )

    print_live_status()

    print("\nCSV records saved to:")
    print(os.path.abspath(EXPORT_FILE))


# ==========================================
# MAIN MONITOR
# ==========================================

def start_monitor():

    global total_packets_captured
    global total_flows_created

    stop_event.clear()

    adapter, npcap_interface = get_active_npcap_interface()

    print("\n===================================")
    print("   WiSecure Persistent Flow Tracker")
    print("===================================")

    print("Adapter:", adapter["name"])
    print("Idle timeout:", IDLE_TIMEOUT, "seconds")
    print("Export file:", EXPORT_FILE)

    print("\nMonitoring started.")
    print("Press CTRL+C to stop monitoring.")

    sniffer = AsyncSniffer(
        iface=npcap_interface,
        store=False,
        prn=packet_handler
    )

    last_status_time = time.monotonic()

    try:

        sniffer.start()

        while not stop_event.wait(1):

            expire_idle_flows()

            current_time = time.monotonic()

            if current_time - last_status_time >= STATUS_INTERVAL:

                print_live_status()

                last_status_time = current_time

    except KeyboardInterrupt:

        print("\nKeyboard interrupt received.")

    finally:

        shutdown_tracker(sniffer)


# ==========================================
# PROGRAM ENTRY
# ==========================================

if __name__ == "__main__":

    try:

        start_monitor()

    except KeyboardInterrupt:

        print("\nMonitoring interrupted.")

    except Exception as error:

        print("\nPersistent flow tracker failed:")
        print(error)
