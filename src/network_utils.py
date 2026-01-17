"""Network utilities for the MITM attack tool.

Includes raw socket handling for low-latency packet transmission.
"""

import socket
from pathlib import Path
import json

import click
from scapy.all import ( # type: ignore[import-untyped,attr-defined]  # pylint: disable=no-name-in-module
    conf,
    get_if_addr,
    Ether,
    sendp,
    IP,
    ARP,
    UDP,
    TCP,
    DNS,
    DNSQR,
    sr1,
    srp,
    SndRcvList
)


def get_interface_info(user_iface: str | None) -> tuple[str, str]:
    """
    Return (iface, ip).
    If user_iface is None, fall back to Scapy's default iface.

    Args:
        user_iface: User-specified interface or None for auto-detect

    Returns:
        Tuple of (interface_name, ip_address)
    """
    iface_obj = user_iface or conf.iface
    iface = str(iface_obj)
    ip = get_if_addr(iface)
    return iface, ip


def init_raw_socket(iface: str) -> socket.socket | None:
    """
    Initialise a raw layer-2 socket for fast packet transmission.

    Raw sockets bypass Scapy's sendp() overhead, saving ~0.5ms per packet.
    Falls back gracefully to None if creation fails (e.g., on non-Linux systems).

    Args:
        iface: Network interface name

    Returns:
        Raw socket object or None if creation failed
    """
    try:
        # AF_PACKET + SOCK_RAW = layer 2 raw socket (Linux only)
        raw_sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
        )
        raw_sock.bind((iface, 0))
        # click.echo(f"[+] Raw socket initialised on {iface}")
        return raw_sock
    except (OSError, PermissionError, AttributeError) as e:
        click.echo(f"[!] Warning: Could not create raw socket: {e}")
        click.echo("[!] Falling back to Scapy sendp() (slower)")
        return None


def send_raw_packet(raw_socket: socket.socket | None, packet_bytes: bytes,
                    iface: str) -> bool:
    """
    Send packet using raw socket (fast) or fall back to Scapy sendp().

    Args:
        raw_socket: Raw socket object or None for fallback
        packet_bytes: Raw packet bytes to send
        iface: Network interface for fallback

    Returns:
        True if sent successfully
    """
    if raw_socket:
        try:
            raw_socket.send(packet_bytes)
            return True
        except OSError:
            pass
    # Fallback to Scapy
    sendp(Ether(packet_bytes), iface=iface, verbose=False)
    return True

def load_dns_rules(rules_path: str | Path) -> dict[str, dict[str, str | None]]:
    """
    Load DNS spoofing rules from a JSON file.
    Supports two formats:
    - Simple: {"domain": "ipv4"} - IPv4 only, AAAA returns empty
    - Full: {"domain": {"A": "ipv4", "AAAA": "ipv6"}} - Both record types
    """
    path = Path(rules_path)
    if not path.exists():
        raise FileNotFoundError(f"DNS rules file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        rules = json.load(f)

    if not isinstance(rules, dict):
        raise ValueError("DNS rules must be a JSON object (dict)")

    normalized: dict[str, dict[str, str | None]] = {}
    for key, value in rules.items():
        domain = key.rstrip(".").lower()

        if isinstance(value, str):
            # Simple format: IPv4 only
            normalized[domain] = {"A": value, "AAAA": None}  # type: ignore
        elif isinstance(value, dict):
            # Full format with A and/or AAAA
            normalized[domain] = {
                "A": value.get("A"),
                "AAAA": value.get("AAAA"),
            }
        else:
            raise ValueError(f"Invalid rule format for {key}")

    return normalized

def get_gateway_ip() -> str:
    """Find the default gateway's IP address.

    Returns:
        A str containing the address
    """

    # This should be a guaranteed non-existent address, hence trying to route
    # to it will definitely use the gateway
    route = conf.route.route("192.0.2.0")

    return route[2]

def broadcast_arp_req(interface: str, network_prefix: int, timeout: int, attacker_ip: str) -> SndRcvList:
    """Perform simple network discovery using ARP.

    Sends a broadcast request asking for attacker_ip/network_prefix and collects the answers it receives.

    Returns:
        A SndRcvList containing all answers after timeout s of waiting.
    """
    arp_request = ARP(pdst=f"{attacker_ip}/{network_prefix}")
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    # Send and receive packets
    answered, _ = srp(
        packet,
        iface=interface,
        timeout=timeout,
        retry=1,
        verbose=False
    )

    return answered

def explore_hosts(
    attacker_ip: str, gateway_ip: str, answered: SndRcvList
) -> list[dict[str, str]]:
    """
    Tries to guess what role(s) hosts in the network have.

    Arguments:
        attacker_ip (str): Attacker's IP address
        gateway_ip (str): IP address of gateway
        answered (SndRcvList): The list of responses to the ARP request returned by `broadcast_arp_req`

    Returns:
        A structured representation of hosts - IP address, MAC address and any extra information that was discovered.
    """
    hosts = []

    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        extra = []

        # Special cases
        if ip == attacker_ip:
            continue

        if ip == gateway_ip:
            extra.append("Gateway")
        if is_dns_server(ip):
            extra.append("DNS")
        if is_tcp_port_open(ip, 80):
            extra.append("HTTP")
        if is_tcp_port_open(ip, 443):
            extra.append("HTTPS")

        hosts.append({"ip": ip, "mac": mac, "extra": ", ".join(extra)})

    return hosts

def is_dns_server(ip: str, timeout: int = 1) -> bool:
    """
    Check whether a host behaves like a DNS server.
    """

    dns_query = IP(dst=ip) / UDP(dport=53) / DNS(
        rd=1,
        qd=DNSQR(qname="example.com")
    )

    response = sr1(dns_query, timeout=timeout, verbose=False)

    if response is None:
        return False

    if not response.haslayer(UDP) or response[UDP].sport != 53:
        return False

    if not response.haslayer(DNS):
        return False

    dns = response[DNS]

    # Must actually be a response
    if dns.qr != 1:
        return False

    return True

def is_tcp_port_open(ip: str, port: int, timeout: int = 1):
    """
    Check if a TCP port is open using SYN probing.
    """

    syn = IP(dst=ip) / TCP(dport=port, flags="S")
    response = sr1(syn, timeout=timeout, verbose=False)

    if response is None:
        return False

    if response.haslayer(TCP):
        flags = response[TCP].flags
        if not flags:
            return False

        # SYN-ACK: open
        if "S" in flags and "A" in flags:
            return True

    return False
