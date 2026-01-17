"""
Simple certificate generation for SSL stripping lab.
Creates a self-signed certificate for bank.com.
"""
import subprocess
import os
from click import style
from pathlib import Path


def generate_bank_cert(cert_dir: str = ".") -> tuple[str, str]:
    """
    Generate self-signed certificate for bank.com.
    
    Returns:
        Tuple of (cert_path, key_path)
    """
    cert_dir = Path(cert_dir)
    cert_dir.mkdir(exist_ok=True)
    
    cert_path = cert_dir / "bank_cert.pem"
    key_path = cert_dir / "bank_key.pem"
    
    # Check if already exists
    if cert_path.exists() and key_path.exists():
        print(style(f"Using existing certificates: {cert_path}, {key_path}", fg="yellow"))
        return str(cert_path), str(key_path)
    
    # Generate self-signed certificate for bank.com
    cmd = [
        "openssl", "req", "-x509",
        "-newkey", "rsa:2048",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", "365",
        "-nodes",
        "-subj", "/CN=bank.com"
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(style(f"Generated certificate for bank.com", fg="yellow"))
        print(style(f"    Cert: {cert_path}", fg="yellow"))
        print(style(f"    Key:  {key_path}", fg="yellow"))
        return str(cert_path), str(key_path)
    except subprocess.CalledProcessError as e:
        print(f"Failed to generate certificate: {e}")
        print(f"Make sure openssl is installed")
        raise


if __name__ == "__main__":
    cert, key = generate_bank_cert()
    print(f"Successfully generated:\n  Cert: {cert}\n  Key: {key}")
