#!/usr/bin/env python3
"""
One-shot helper: convert src/ca_cert.h into mqtt_*.pem next to this script
(or into --out-dir). Run on a machine that has the Zephyr app sources, then
copy the three PEM files + https_test_server.py to the provision PC.

  python extract_mqtt_pems_from_ca_cert.py
  python extract_mqtt_pems_from_ca_cert.py --ca-cert ..\\src\\ca_cert.h --out-dir .
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def extract_array(text: str, name: str) -> bytes:
    m = re.search(rf"const unsigned char {name}\[\] = \{{(.*?)\}};", text, re.S)
    if not m:
        raise SystemExit(f"Could not find array {name}")
    nums = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", m.group(1))]
    return bytes(nums)


def extract_private_key(text: str) -> str:
    idx = text.find("#define PRIVATE_KEY")
    if idx < 0:
        raise SystemExit("Could not find PRIVATE_KEY")
    chunk = text[idx : idx + 4000]
    strs: list[str] = []
    for line in chunk.splitlines()[1:]:
        line = line.strip()
        if not line.startswith('"'):
            break
        strs.extend(re.findall(r'"([^"]*)"', line))
    pk = "".join(strs).encode("utf-8").decode("unicode_escape")
    if not pk.endswith("\n"):
        pk += "\n"
    return pk


def main() -> None:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--ca-cert",
        default=str(here.parent / "src" / "ca_cert.h"),
        help="Path to ca_cert.h",
    )
    ap.add_argument("--out-dir", default=str(here), help="Where to write mqtt_*.pem")
    args = ap.parse_args()

    src = Path(args.ca_cert)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    text = src.read_text(encoding="utf-8", errors="replace")

    ca = extract_array(text, "ca_pem")
    client = extract_array(text, "client_cert_pem")
    key = extract_private_key(text)

    (out / "mqtt_ca.pem").write_bytes(ca)
    (out / "mqtt_client.pem").write_bytes(client)
    (out / "mqtt_key.pem").write_text(key, encoding="ascii")

    print(f"Wrote {out / 'mqtt_ca.pem'} ({len(ca)} bytes)")
    print(f"Wrote {out / 'mqtt_client.pem'} ({len(client)} bytes)")
    print(f"Wrote {out / 'mqtt_key.pem'} ({len(key)} bytes)")
    print("Copy these three files + https_test_server.py to the other PC, then:")
    print("  python https_test_server.py")


if __name__ == "__main__":
    main()
