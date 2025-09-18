#!/usr/bin/env python3
import argparse
import base64
from nacl.public import PrivateKey

def main():
    parser = argparse.ArgumentParser(description="Generate X25519 key pairs.")
    parser.add_argument("--name", required=True, help="Name for the key files (e.g., server, client).")
    parser.add_argument("--out-dir", default=".", help="Output directory for the key files.")
    args = parser.parse_args()

    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    priv_key_b64 = base64.b64encode(bytes(private_key)).decode('ascii')
    pub_key_b64 = base64.b64encode(bytes(public_key)).decode('ascii')

    with open(f"{args.out_dir}/{args.name}.key", "w") as f:
        f.write(priv_key_b64)

    with open(f"{args.out_dir}/{args.name}.pub", "w") as f:
        f.write(pub_key_b64)

    print(f"Generated key pair for '{args.name}' in '{args.out_dir}/'")
    print(f"  Private key: {args.out_dir}/{args.name}.key")
    print(f"  Public key:  {args.out_dir}/{args.name}.pub")

if __name__ == "__main__":
    main()
