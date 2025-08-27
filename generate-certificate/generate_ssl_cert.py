#!/usr/bin/env python3
"""
Self-Signed SSL Certificate Generator

This script generates a self-signed SSL certificate and private key
for any specified domain, suitable for local development and testing.

Requirements:
    pip install cryptography

Usage:
    python generate_ssl_cert.py [options]
    
Examples:
    python generate_ssl_cert.py
    python generate_ssl_cert.py --domain "*.example.com" --days 730
    python generate_ssl_cert.py -d "localhost" -c "localhost.crt" -k "localhost.key"
"""

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_self_signed_cert(
    domain="*.dev.test",
    cert_file="dev.test.crt",
    key_file="dev.test.key",
    days_valid=365
):
    """
    Generate a self-signed SSL certificate for the specified domain.
    
    Args:
        domain (str): Domain name (supports wildcards)
        cert_file (str): Output certificate file name
        key_file (str): Output private key file name
        days_valid (int): Certificate validity period in days
    """
    
    print(f"Generating self-signed certificate for domain: {domain}")
    
    # Generate private key
    print("Generating RSA private key (2048 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create certificate subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Development"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dev Test Organization"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    
    # Set certificate validity period
    valid_from = datetime.now(timezone.utc)
    valid_to = valid_from + timedelta(days=days_valid)
    
    print(f"Certificate will be valid from {valid_from} to {valid_to}")
    
    # Create certificate
    print("Creating certificate...")
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        # Subject Alternative Names - important for wildcard certificates
        x509.SubjectAlternativeName([
            x509.DNSName(domain),
            x509.DNSName("dev.test"),  # Also include the base domain
            x509.DNSName("localhost"),  # Include localhost for local testing
        ]),
        critical=False,
    ).add_extension(
        # Key usage
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        # Extended key usage
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True,
    ).add_extension(
        # Basic constraints
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    # Write private key to file
    print(f"Writing private key to {key_file}...")
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate to file
    print(f"Writing certificate to {cert_file}...")
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Set appropriate file permissions (read-only for others)
    os.chmod(key_file, 0o600)  # Private key should be readable only by owner
    os.chmod(cert_file, 0o644)  # Certificate can be readable by others
    
    print("\n" + "="*60)
    print("SSL Certificate generated successfully!")
    print("="*60)
    print(f"Domain: {domain}")
    print(f"Certificate file: {cert_file}")
    print(f"Private key file: {key_file}")
    print(f"Valid for: {days_valid} days")
    print("\nTo use with nginx, add these lines to your server block:")
    print(f"    ssl_certificate     {os.path.abspath(cert_file)};")
    print(f"    ssl_certificate_key {os.path.abspath(key_file)};")
    print("\nTo trust this certificate in your browser:")
    print("1. Import the .crt file into your browser's trusted certificates")
    print("2. Or add it to your system's certificate store")
    print("\nNote: This is a self-signed certificate for development use only!")


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate self-signed SSL certificates for development",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --domain "*.example.com" --days 730
  %(prog)s -d "localhost" -c "localhost.crt" -k "localhost.key"
  %(prog)s --domain "api.myapp.local" --cert-file "api.crt" --key-file "api.key" --days 90
        """
    )
    
    parser.add_argument(
        "-d", "--domain",
        default="*.dev.test",
        help="Domain name for the certificate (supports wildcards, default: *.dev.test)"
    )
    
    parser.add_argument(
        "-c", "--cert-file",
        default="dev.test.crt",
        help="Output certificate file name (default: dev.test.crt)"
    )
    
    parser.add_argument(
        "-k", "--key-file", 
        default="dev.test.key",
        help="Output private key file name (default: dev.test.key)"
    )
    
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Certificate validity period in days (default: 365)"
    )
    
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Overwrite existing files without prompting"
    )
    
    return parser.parse_args()


def check_dependencies():
    """Check if required dependencies are installed."""
    try:
        import cryptography
        return True
    except ImportError:
        print("Error: The 'cryptography' library is required but not installed.")
        print("Please install it using: pip install cryptography")
        return False


def main():
    """Main function."""
    if not check_dependencies():
        sys.exit(1)
    
    # Parse command-line arguments
    args = parse_arguments()
    
    print("Self-Signed SSL Certificate Generator")
    print("=" * 40)
    print(f"Domain: {args.domain}")
    print(f"Certificate file: {args.cert_file}")
    print(f"Private key file: {args.key_file}")
    print(f"Validity period: {args.days} days")
    print()
    
    # Check if files already exist
    if not args.force and (os.path.exists(args.cert_file) or os.path.exists(args.key_file)):
        response = input(f"Files {args.cert_file} or {args.key_file} already exist. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Aborted.")
            sys.exit(0)
    
    try:
        generate_self_signed_cert(args.domain, args.cert_file, args.key_file, args.days)
    except Exception as e:
        print(f"Error generating certificate: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
