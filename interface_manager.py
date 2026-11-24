
import socket
import re
import winreg
import psutil
from scapy.all import get_if_list


NETWORK_CLASS_KEY = (
    r"SYSTEM\CurrentControlSet\Control\Network"
    r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
)


def get_network_interfaces():
    """Discover network adapters and IPv4 addresses."""

    interfaces = []
    adapter_stats = psutil.net_if_stats()
    adapter_addresses = psutil.net_if_addrs()

    for name, addresses in adapter_addresses.items():
        stats = adapter_stats.get(name)

        ipv4_addresses = [
            address.address
            for address in addresses
            if address.family == socket.AF_INET
            and not address.address.startswith("127.")
        ]

        for ip_address in ipv4_addresses:
            is_link_local = ip_address.startswith("169.254.")

            interfaces.append({
                "name": name,
                "ip_address": ip_address,
                "is_up": stats.isup if stats else False,
                "speed_mbps": stats.speed if stats else 0,
                "is_link_local": is_link_local,
                "is_preferred": (
                    stats.isup if stats else False
                ) and not is_link_local
            })

    return interfaces


def get_scapy_interfaces():
    """Return interfaces available through Npcap."""
    return get_if_list()


def get_adapter_guid(adapter_name):
    """
    Find a Windows adapter GUID using its friendly name.
    """

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            NETWORK_CLASS_KEY
        ) as network_key:

            index = 0

            while True:
                try:
                    guid = winreg.EnumKey(network_key, index)
                    index += 1

                    connection_path = (
                        NETWORK_CLASS_KEY
                        + "\\"
                        + guid
                        + r"\Connection"
                    )

                    try:
                        with winreg.OpenKey(
                            winreg.HKEY_LOCAL_MACHINE,
                            connection_path
                        ) as connection_key:

                            name, _ = winreg.QueryValueEx(
                                connection_key, "Name"
                            )

                            if name.casefold() == adapter_name.casefold():
                                return guid

                    except FileNotFoundError:
                        continue

                except OSError:
                    break

    except OSError as error:
        print("Windows adapter lookup failed:", error)

    return None


def get_npcap_interface(adapter_guid):
    """Match an adapter GUID to its Npcap interface."""

    if not adapter_guid:
        return None

    normalized_guid = adapter_guid.strip("{}").lower()

    for interface in get_scapy_interfaces():
        match = re.search(
            r"NPF_\{([^}]+)\}",
            interface,
            re.IGNORECASE
        )

        if match and match.group(1).lower() == normalized_guid:
            return interface

    return None


def get_active_interface():
    """Select an active adapter with a usable IPv4 address."""

    interfaces = get_network_interfaces()

    preferred = [
        interface for interface in interfaces
        if interface["is_preferred"]
    ]

    # Prefer Wi-Fi when it is active.
    for interface in preferred:
        if interface["name"].casefold() == "wi-fi":
            return interface

    return preferred[0] if preferred else None


def get_active_npcap_interface():
    """Automatically resolve the active adapter to Npcap."""

    adapter = get_active_interface()

    if not adapter:
        raise RuntimeError("No active network adapter found.")

    guid = get_adapter_guid(adapter["name"])

    if not guid:
        raise RuntimeError(
            f"Could not find GUID for {adapter['name']}."
        )

    npcap_interface = get_npcap_interface(guid)

    if not npcap_interface:
        raise RuntimeError(
            f"No Npcap interface found for {adapter['name']}."
        )

    return adapter, npcap_interface


if __name__ == "__main__":

    print("\n===== WiSecure Dynamic Interface Manager =====")

    try:
        adapter, npcap = get_active_npcap_interface()

        print("Selected adapter:", adapter["name"])
        print("IP address:", adapter["ip_address"])
        print("Link speed:", adapter["speed_mbps"], "Mbps")
        print("Adapter GUID:", get_adapter_guid(adapter["name"]))
        print("Npcap interface:", npcap)
        print("\nSUCCESS: Dynamic interface selection working!")

    except RuntimeError as error:
        print("ERROR:", error)
