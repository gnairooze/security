#!/usr/bin/env python3
"""
CA Certificate and Server Certificate Generator for *.dev.test

This script generates:
1. A Certificate Authority (CA) certificate and private key
2. A server certificate signed by the CA for *.dev.test

The CA certificate can be imported into browsers as a trusted authority,
eliminating security warnings for all certificates signed by this CA.

Requirements:
    pip install cryptography

Usage:
    python generate_ca_and_cert.py
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_ca_certificate(
    ca_cert_file="dev-test-ca.crt",
    ca_key_file="dev-test-ca.key",
    days_valid=3650  # 10 years for CA
):
    """
    Generate a Certificate Authority (CA) certificate and private key.
    
    Args:
        ca_cert_file (str): Output CA certificate file name
        ca_key_file (str): Output CA private key file name
        days_valid (int): CA certificate validity period in days
    
    Returns:
        tuple: (ca_certificate, ca_private_key)
    """
    
    print("Generating Certificate Authority (CA)...")
    
    # Generate CA private key
    print("Generating CA RSA private key (4096 bits)...")
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Create CA certificate subject
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Development"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dev Test CA Organization"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Dev Test Local CA"),
    ])
    
    # Set CA certificate validity period
    valid_from = datetime.now(timezone.utc)
    valid_to = valid_from + timedelta(days=days_valid)
    
    print(f"CA Certificate will be valid from {valid_from} to {valid_to}")
    
    # Create CA certificate
    print("Creating CA certificate...")
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_subject  # Self-signed CA
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        # Basic constraints - THIS IS A CA CERTIFICATE
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        # Key usage for CA
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,  # Can sign certificates
            crl_sign=True,      # Can sign CRLs
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        # Subject Key Identifier
        x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())
    
    # Write CA private key to file
    print(f"Writing CA private key to {ca_key_file}...")
    with open(ca_key_file, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write CA certificate to file
    print(f"Writing CA certificate to {ca_cert_file}...")
    with open(ca_cert_file, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    # Set appropriate file permissions
    os.chmod(ca_key_file, 0o600)  # Private key should be readable only by owner
    os.chmod(ca_cert_file, 0o644)  # Certificate can be readable by others
    
    return ca_cert, ca_private_key


def generate_server_certificate(
    ca_cert,
    ca_private_key,
    domain="lb.dev.test",
    cert_file="dev.test.crt",
    key_file="dev.test.key",
    days_valid=365
):
    """
    Generate a server certificate signed by the CA.
    
    Args:
        ca_cert: CA certificate object
        ca_private_key: CA private key object
        domain (str): Domain name (supports wildcards)
        cert_file (str): Output certificate file name
        key_file (str): Output private key file name
        days_valid (int): Certificate validity period in days
    """
    
    print(f"Generating server certificate for domain: {domain}")
    
    # Generate server private key
    print("Generating server RSA private key (2048 bits)...")
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create server certificate subject
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Development"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dev Test Organization"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    
    # Set server certificate validity period
    valid_from = datetime.now(timezone.utc)
    valid_to = valid_from + timedelta(days=days_valid)
    
    print(f"Server certificate will be valid from {valid_from} to {valid_to}")
    
    # Create server certificate signed by CA
    print("Creating server certificate signed by CA...")
    server_cert = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        ca_cert.subject  # Signed by CA
    ).public_key(
        server_private_key.public_key()
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
            x509.IPAddress(IPv4Address("127.0.0.1")),  # Include localhost IP
        ]),
        critical=False,
    ).add_extension(
        # Key usage for server certificate
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,  # Server cert cannot sign other certs
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
        # Basic constraints - NOT A CA CERTIFICATE
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        # Authority Key Identifier (links to CA)
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    ).add_extension(
        # Subject Key Identifier
        x509.SubjectKeyIdentifier.from_public_key(server_private_key.public_key()),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())  # Sign with CA private key
    
    # Write server private key to file
    print(f"Writing server private key to {key_file}...")
    with open(key_file, "wb") as f:
        f.write(server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write server certificate to file
    print(f"Writing server certificate to {cert_file}...")
    with open(cert_file, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    
    # Set appropriate file permissions
    os.chmod(key_file, 0o600)  # Private key should be readable only by owner
    os.chmod(cert_file, 0o644)  # Certificate can be readable by others


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
    
    print("CA and Server Certificate Generator")
    print("=" * 40)
    
    # Configuration
    ca_cert_file = "dev-test-ca.crt"
    ca_key_file = "dev-test-ca.key"
    server_domain = "lb.dev.test"
    server_cert_file = "dev.test.crt"
    server_key_file = "dev.test.key"
    ca_days_valid = 3650  # 10 years
    server_days_valid = 365  # 1 year
    
    # Check if files already exist
    files_to_check = [ca_cert_file, ca_key_file, server_cert_file, server_key_file]
    existing_files = [f for f in files_to_check if os.path.exists(f)]
    
    if existing_files:
        print(f"\nThe following files already exist: {', '.join(existing_files)}")
        response = input("Overwrite existing files? (y/N): ")
        if response.lower() != 'y':
            print("Aborted.")
            sys.exit(0)
    
    try:
        # Generate CA certificate
        ca_cert, ca_private_key = generate_ca_certificate(
            ca_cert_file, ca_key_file, ca_days_valid
        )
        
        # Generate server certificate signed by CA
        generate_server_certificate(
            ca_cert, ca_private_key, server_domain, 
            server_cert_file, server_key_file, server_days_valid
        )
        
        print("\n" + "="*60)
        print("SSL Certificates generated successfully!")
        print("="*60)
        print(f"CA Certificate: {ca_cert_file}")
        print(f"CA Private Key: {ca_key_file}")
        print(f"Server Certificate: {server_cert_file}")
        print(f"Server Private Key: {server_key_file}")
        print(f"Server Domain: {server_domain}")
        print(f"CA Valid for: {ca_days_valid} days")
        print(f"Server Valid for: {server_days_valid} days")
        
        print("\nTo use with nginx, add these lines to your server block:")
        print(f"    ssl_certificate     {os.path.abspath(server_cert_file)};")
        print(f"    ssl_certificate_key {os.path.abspath(server_key_file)};")
        
        print(f"\nTo trust these certificates in Firefox:")
        print("1. Go to Settings → Privacy & Security → Certificates → View Certificates")
        print("2. Click 'Import' in the Authorities tab")
        print(f"3. Select the CA certificate file: {ca_cert_file}")
        print("4. Check 'Trust this CA to identify websites'")
        print("5. Restart Firefox")
        
        print(f"\nFor Chrome/Edge (Windows):")
        print(f"1. Double-click the CA certificate file: {ca_cert_file}")
        print("2. Click 'Install Certificate'")
        print("3. Choose 'Local Machine' → Next")
        print("4. Select 'Place all certificates in the following store'")
        print("5. Browse → 'Trusted Root Certification Authorities' → Next → Finish")
        
        print("\n⚠️  IMPORTANT: Import the CA certificate (.crt), not the server certificate!")
        print("The CA certificate allows your browser to trust all certificates signed by this CA.")
        
    except Exception as e:
        print(f"Error generating certificates: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
