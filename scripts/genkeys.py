#!/usr/bin/env python3
import argparse
import base64
import os
from nacl.public import PrivateKey

def main():
    """
    Generates and saves X25519 key pairs for PyTunnel.
    """
    parser = argparse.ArgumentParser(description="Generate X25519 key pairs for PyTunnel.")
    parser.add_argument("--name", required=True, help="A name for the key files (e.g., 'server' or 'client').")
    parser.add_argument("--out-dir", default=".", help="The directory to save the key files in.")
    args = parser.parse_args()

    # Ensure the output directory exists
    os.makedirs(args.out_dir, exist_ok=True)

    # Generate the key pair
    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    # Base64 encode the keys for easy storage and transport
    private_key_b64 = base64.b64encode(bytes(private_key)).decode('ascii')
    public_key_b64 = base64.b64encode(bytes(public_key)).decode('ascii')

    private_key_path = os.path.join(args.out_dir, f"{args.name}.key")
    public_key_path = os.path.join(args.out_dir, f"{args.name}.pub")

    # Write the keys to their respective files
    with open(private_key_path, 'w') as f:
        f.write(private_key_b64)

    with open(public_key_path, 'w') as f:
        f.write(public_key_b64)

    print(f"Successfully generated and saved keys for '{args.name}':")
    print(f"  Private Key: {private_key_path}")
    print(f"  Public Key:  {public_key_path}")

if __name__ == "__main__":
    main()
