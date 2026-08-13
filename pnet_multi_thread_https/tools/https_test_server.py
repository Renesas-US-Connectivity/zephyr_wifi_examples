#!/usr/bin/env python3
"""
Phase 4 LAN HTTPS provision server for pnet_multi_thread.

Copy this script PLUS the three MQTT PEM files to the PC that serves
provisioning (does not need the full Zephyr app tree):

  https_test_server.py
  mqtt_ca.pem
  mqtt_client.pem
  mqtt_key.pem

Then on that PC:

  python https_test_server.py

Optional: --cert/--key for the HTTPS listener (else auto cert.pem/key.pem).
Optional: explicit --mqtt-ca / --mqtt-client-cert / --mqtt-client-key paths.
"""

from __future__ import annotations

import argparse
import json
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent


def make_self_signed(cert_path: Path, key_path: Path) -> None:
    try:
        from OpenSSL import crypto
    except ImportError as exc:
        raise SystemExit(
            "Need --cert/--key, or: pip install pyopenssl\n"
            "Then re-run without --cert/--key to auto-generate."
        ) from exc

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "192.168.50.243"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    cert_path.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    key_path.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    print(f"Generated HTTPS server cert: {cert_path}")


def load_pem(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(
            f"Missing PEM: {path}\n"
            "Put mqtt_ca.pem, mqtt_client.pem, mqtt_key.pem next to this script,\n"
            "or pass --mqtt-ca / --mqtt-client-cert / --mqtt-client-key."
        )
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if "BEGIN" not in text:
        raise SystemExit(f"Not a PEM file: {path}")
    if not text.endswith("\n"):
        text += "\n"
    return text


def resolve_mqtt_pem(arg: str | None, default_name: str) -> Path:
    if arg:
        return Path(arg)
    return HERE / default_name


def build_cfg(args: argparse.Namespace) -> dict:
    ca = resolve_mqtt_pem(args.mqtt_ca, "mqtt_ca.pem")
    client = resolve_mqtt_pem(args.mqtt_client_cert, "mqtt_client.pem")
    key = resolve_mqtt_pem(args.mqtt_client_key, "mqtt_key.pem")
    return {
        "status": "ok",
        "mqtt_host": args.mqtt_host,
        "mqtt_port": args.mqtt_port,
        "mqtt_client_id": args.mqtt_client_id,
        "mqtt_ca_pem": load_pem(ca),
        "mqtt_client_cert_pem": load_pem(client),
        "mqtt_private_key_pem": load_pem(key),
    }


def main():
    ap = argparse.ArgumentParser(
        description="HTTPS MQTT provision server (Phase 4). "
        "Default: load mqtt_*.pem from the script directory."
    )
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=4443)
    ap.add_argument("--cert", default=None, help="HTTPS server PEM cert")
    ap.add_argument("--key", default=None, help="HTTPS server PEM key")
    ap.add_argument("--mqtt-host", default="192.168.50.243")
    ap.add_argument("--mqtt-port", type=int, default=8883)
    ap.add_argument("--mqtt-client-id", default="pnet-mt-client")
    ap.add_argument("--mqtt-ca", default=None, help="MQTT CA PEM (default: ./mqtt_ca.pem)")
    ap.add_argument(
        "--mqtt-client-cert",
        default=None,
        help="MQTT client cert PEM (default: ./mqtt_client.pem)",
    )
    ap.add_argument(
        "--mqtt-client-key",
        default=None,
        help="MQTT client key PEM (default: ./mqtt_key.pem)",
    )
    args = ap.parse_args()

    cfg = build_cfg(args)
    body = json.dumps(cfg).encode("utf-8")
    print(f"Provision JSON size: {len(body)} bytes")

    if args.cert and args.key:
        cert_file, key_file = args.cert, args.key
    elif args.cert or args.key:
        raise SystemExit("Provide both --cert and --key, or neither")
    else:
        cert_path = HERE / "cert.pem"
        key_path = HERE / "key.pem"
        if not (cert_path.is_file() and key_path.is_file()):
            make_self_signed(cert_path, key_path)
        else:
            print(f"Using existing {cert_path.name} / {key_path.name}")
        cert_file, key_file = str(cert_path), str(key_path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            print(f"GET {self.path} from {self.client_address[0]} -> {len(body)} bytes")

        def log_message(self, fmt, *a):
            print(f"[HTTP] {self.address_string()} - {fmt % a}")

    httpd = HTTPServer((args.bind, args.port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"HTTPS provision on https://{args.bind}:{args.port}/")
    print(
        f"MQTT endpoint in JSON: {args.mqtt_host}:{args.mqtt_port} "
        f"id={args.mqtt_client_id}"
    )
    httpd.serve_forever()


if __name__ == "__main__":
    main()
