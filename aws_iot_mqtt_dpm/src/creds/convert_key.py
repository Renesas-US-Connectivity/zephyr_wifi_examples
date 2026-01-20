# Copyright (c) 2023
# SPDX-License-Identifier: Apache-2.0

import os


def bin2array(name, fin, fout):
    with open(fin, 'rb') as f:
        data = f.read()

    # Add NULL terminator (required by Zephyr TLS)
    data += b'\0'

    with open(fout, 'w') as f:
        f.write("#include <stdint.h>\n\n")
        f.write(f"const uint8_t {name}[] = {{")

        for i in range(0, len(data), 16):
            f.write("\n    ")
            f.write(", ".join(f"0x{b:02x}" for b in data[i:i + 16]))
            f.write(",")

        f.write("\n};\n\n")
        f.write(f"const uint32_t {name}_len = sizeof({name});\n")

    print(f"[OK] {os.path.basename(fin)}  ->  {os.path.basename(fout)}")


if __name__ == "__main__":
    creds_dir = os.path.dirname(os.path.realpath(__file__))

    cert_found = False
    key_found = False
    ca_found = False

    for fname in os.listdir(creds_dir):
        path = os.path.join(creds_dir, fname)

        if not os.path.isfile(path):
            continue

        # Device certificate (RSA or ECC)
        if fname.endswith(".crt") and "AmazonRootCA" not in fname:
            bin2array("public_cert", path,
                      os.path.join(creds_dir, "cert.c"))
            cert_found = True

        # Device private key (RSA or ECC)
        elif fname.endswith(".key"):
            bin2array("private_key", path,
                      os.path.join(creds_dir, "key.c"))
            key_found = True

        # Root CA (always AmazonRootCA1)
        elif fname == "AmazonRootCA1.pem":
            bin2array("ca_cert", path,
                      os.path.join(creds_dir, "ca.c"))
            ca_found = True

    if not cert_found:
        print("❌ ERROR: No device certificate (*.crt) found")

    if not key_found:
        print("❌ ERROR: No device private key (*.key) found")

    if not ca_found:
        print("❌ ERROR: AmazonRootCA1.pem not found")

    if cert_found and key_found and ca_found:
        print("\n✅ Certificate conversion completed successfully")
