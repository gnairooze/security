#!/usr/bin/env python3
"""
Code Signing Certificate Generator

This script generates:
1. A Certificate Authority (CA) certificate for code signing
2. A code signing certificate signed by the CA

The code signing certificate can be used to sign executables, scripts,
and other code artifacts for development and testing purposes.

Requirements:
    pip install cryptography

Usage:
    python generate_code_signing_cert.py
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_code_signing_ca(
    ca_cert_file="code-signing-ca.crt",
    ca_key_file="code-signing-ca.key",
    days_valid=3650  # 10 years for CA
):
    """
    Generate a Certificate Authority (CA) certificate for code signing.
    
    Args:
        ca_cert_file (str): Output CA certificate file name
        ca_key_file (str): Output CA private key file name
        days_valid (int): CA certificate validity period in days
    
    Returns:
        tuple: (ca_certificate, ca_private_key)
    """
    
    print("Generating Code Signing Certificate Authority (CA)...")
    
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
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dev Code Signing CA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Dev Code Signing Root CA"),
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
        # Extended Key Usage for CA - can issue code signing certs
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CODE_SIGNING,
        ]),
        critical=False,
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


def generate_code_signing_certificate(
    ca_cert,
    ca_private_key,
    common_name="Dev Code Signing Certificate",
    cert_file="code-signing.crt",
    key_file="code-signing.key",
    days_valid=365
):
    """
    Generate a code signing certificate signed by the CA.
    
    Args:
        ca_cert: CA certificate object
        ca_private_key: CA private key object
        common_name (str): Common name for the code signing certificate
        cert_file (str): Output certificate file name
        key_file (str): Output private key file name
        days_valid (int): Certificate validity period in days
    """
    
    print(f"Generating code signing certificate: {common_name}")
    
    # Generate code signing private key
    print("Generating code signing RSA private key (2048 bits)...")
    cs_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create code signing certificate subject
    cs_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Development"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dev Organization"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Set code signing certificate validity period
    valid_from = datetime.now(timezone.utc)
    valid_to = valid_from + timedelta(days=days_valid)
    
    print(f"Code signing certificate will be valid from {valid_from} to {valid_to}")
    
    # Create code signing certificate signed by CA
    print("Creating code signing certificate signed by CA...")
    cs_cert = x509.CertificateBuilder().subject_name(
        cs_subject
    ).issuer_name(
        ca_cert.subject  # Signed by CA
    ).public_key(
        cs_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        # Key usage for code signing certificate
        x509.KeyUsage(
            digital_signature=True,  # Required for code signing
            key_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,     # Code signing cert cannot sign other certs
            crl_sign=False,
            content_commitment=True, # Non-repudiation for code signing
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        # Extended key usage - CODE SIGNING
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CODE_SIGNING,  # This is the key extension!
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
        x509.SubjectKeyIdentifier.from_public_key(cs_private_key.public_key()),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())  # Sign with CA private key
    
    # Write code signing private key to file
    print(f"Writing code signing private key to {key_file}...")
    with open(key_file, "wb") as f:
        f.write(cs_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write code signing certificate to file
    print(f"Writing code signing certificate to {cert_file}...")
    with open(cert_file, "wb") as f:
        f.write(cs_cert.public_bytes(serialization.Encoding.PEM))
    
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
    
    print("Code Signing Certificate Generator")
    print("=" * 40)
    
    # Configuration
    ca_cert_file = "code-signing-ca.crt"
    ca_key_file = "code-signing-ca.key"
    cs_common_name = "Dev Code Signing Certificate"
    cs_cert_file = "code-signing.crt"
    cs_key_file = "code-signing.key"
    ca_days_valid = 3650  # 10 years
    cs_days_valid = 365   # 1 year
    
    # Check if files already exist
    files_to_check = [ca_cert_file, ca_key_file, cs_cert_file, cs_key_file]
    existing_files = [f for f in files_to_check if os.path.exists(f)]
    
    if existing_files:
        print(f"\nThe following files already exist: {', '.join(existing_files)}")
        response = input("Overwrite existing files? (y/N): ")
        if response.lower() != 'y':
            print("Aborted.")
            sys.exit(0)
    
    try:
        # Generate CA certificate
        ca_cert, ca_private_key = generate_code_signing_ca(
            ca_cert_file, ca_key_file, ca_days_valid
        )
        
        # Generate code signing certificate signed by CA
        generate_code_signing_certificate(
            ca_cert, ca_private_key, cs_common_name,
            cs_cert_file, cs_key_file, cs_days_valid
        )
        
        print("\n" + "="*60)
        print("Code Signing Certificates generated successfully!")
        print("="*60)
        print(f"CA Certificate: {ca_cert_file}")
        print(f"CA Private Key: {ca_key_file}")
        print(f"Code Signing Certificate: {cs_cert_file}")
        print(f"Code Signing Private Key: {cs_key_file}")
        print(f"Common Name: {cs_common_name}")
        print(f"CA Valid for: {ca_days_valid} days")
        print(f"Code Signing Valid for: {cs_days_valid} days")
        
        print("\n" + "="*60)
        print("USAGE INSTRUCTIONS")
        print("="*60)
        
        print("\n🔐 IMPORTING CA CERTIFICATE (Required for trust):")
        print("\nWindows:")
        print(f"1. Double-click {ca_cert_file}")
        print("2. Install Certificate → Local Machine → Next")
        print("3. Place in 'Trusted Root Certification Authorities'")
        print("4. Finish")
        
        print("\nmacOS:")
        print(f"sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {ca_cert_file}")
        
        print("\nLinux:")
        print(f"sudo cp {ca_cert_file} /usr/local/share/ca-certificates/")
        print("sudo update-ca-certificates")
        
        print("\n📝 SIGNING CODE EXAMPLES:")
        print("\nSign a PowerShell script (Windows):")
        print(f'Set-AuthenticodeSignature -FilePath "script.ps1" -Certificate (Get-PfxCertificate "{cs_cert_file}")')
        
        print("\nSign with signtool (Windows):")
        print(f'signtool sign /f "{cs_cert_file}" /p "" /t http://timestamp.digicert.com "executable.exe"')
        
        print("\nSign with jarsigner (Java):")
        print("# First convert to PKCS#12 format:")
        print(f'openssl pkcs12 -export -in {cs_cert_file} -inkey {cs_key_file} -out code-signing.p12')
        print('jarsigner -keystore code-signing.p12 -storetype PKCS12 myapp.jar "1"')
        
        print("\nSign with codesign (macOS):")
        print("# Import certificate to keychain first, then:")
        print(f'codesign -s "{cs_common_name}" -v myapp')
        
        print("\n⚠️  IMPORTANT NOTES:")
        print("- These certificates are for DEVELOPMENT/TESTING only")
        print("- Production code signing requires certificates from trusted CAs")
        print("- Keep private keys secure and never share them")
        print("- Some platforms may require additional certificate attributes")
        print(f"- Import the CA certificate ({ca_cert_file}) to trust signed code")
        
    except Exception as e:
        print(f"Error generating certificates: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
