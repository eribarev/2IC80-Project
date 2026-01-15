"""Network utilities for the MITM attack tool.

Includes raw socket handling for low-latency packet transmission.
"""

import socket
import click
from scapy.all import conf, get_if_addr, Ether, sendp  # type: ignore[import-untyped,attr-defined]  # pylint: disable=no-name-in-module


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
