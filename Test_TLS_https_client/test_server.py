import http.server
import ssl
import os
import ipaddress
from datetime import datetime, timedelta, timezone

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Please install cryptography: pip install cryptography")
    exit(1)

import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def generate_self_signed_cert(ip_address):
    # Always overwrite or generate to match the current IP
    print(f"Generating self-signed SSL certificate (RSA 2048-bit) for IP: {ip_address}...")
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Jose"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Renesas Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, str(ip_address)),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - timedelta(days=1)
    ).not_valid_after(
        now + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip_address))]),
        critical=False,
    ).sign(key, hashes.SHA256())

    with open("server.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

class TestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"\n=== GET Request received for {self.path} ===")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "success", "method": "GET"}')

    def do_PUT(self):
        print(f"\n=== PUT Request received for {self.path} ===")
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length)
            print(f"Body: {post_data.decode('utf-8', errors='ignore')}")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "success", "method": "PUT"}')

if __name__ == "__main__":
    local_ip = get_local_ip()
    generate_self_signed_cert(local_ip)
    server_address = ('0.0.0.0', 4443)
    httpd = http.server.HTTPServer(server_address, TestHandler)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    
    context.load_cert_chain(certfile="server.pem")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"HTTPS Test Server running on https://{local_ip}:4443/")
    httpd.serve_forever()
