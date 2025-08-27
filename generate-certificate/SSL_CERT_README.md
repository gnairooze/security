# SSL Certificate Generator

A Python script to generate self-signed SSL certificates for development and testing purposes.

## Requirements

```bash
pip install cryptography
```

## Usage

### Basic Usage

Generate a certificate for the default domain (`*.dev.test`):

```bash
python generate_ssl_cert.py
```

This creates:
- `dev.test.crt` - Certificate file
- `dev.test.key` - Private key file

### Command Line Options

```bash
python generate_ssl_cert.py [options]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--domain` | `-d` | Domain name for the certificate (supports wildcards) | `*.dev.test` |
| `--cert-file` | `-c` | Output certificate file name | `dev.test.crt` |
| `--key-file` | `-k` | Output private key file name | `dev.test.key` |
| `--days` | | Certificate validity period in days | `365` |
| `--force` | `-f` | Overwrite existing files without prompting | `false` |
| `--help` | `-h` | Show help message and exit | |

### Examples

#### Generate certificate for localhost
```bash
python generate_ssl_cert.py --domain "localhost" --cert-file "localhost.crt" --key-file "localhost.key"
```

#### Generate wildcard certificate for custom domain
```bash
python generate_ssl_cert.py --domain "*.example.com" --days 730
```

#### Generate certificate with custom file names
```bash
python generate_ssl_cert.py -d "api.myapp.local" -c "api.crt" -k "api.key" --days 90
```

#### Force overwrite existing files
```bash
python generate_ssl_cert.py --domain "test.local" --force
```

## Certificate Details

The generated certificates include:

- **Algorithm**: RSA 2048-bit
- **Hash**: SHA-256
- **Extensions**: 
  - Subject Alternative Names (SAN)
  - Key Usage
  - Extended Key Usage
  - Basic Constraints
- **Subject Alternative Names**: 
  - The specified domain
  - Base domain (for wildcards)
  - `localhost` (for local testing)

## Using the Certificate

### With Nginx

Add these lines to your server block:

```nginx
ssl_certificate     /path/to/your/certificate.crt;
ssl_certificate_key /path/to/your/private.key;
```

### With Apache

Add these lines to your virtual host:

```apache
SSLCertificateFile /path/to/your/certificate.crt
SSLCertificateKeyFile /path/to/your/private.key
```

### Trusting the Certificate

To avoid browser security warnings:

1. **Chrome/Edge**: Import the `.crt` file into "Trusted Root Certification Authorities"
2. **Firefox**: Go to Settings → Privacy & Security → Certificates → View Certificates → Import
3. **System-wide** (Linux): Copy to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`
4. **System-wide** (macOS): Add to Keychain Access and mark as trusted

## Security Notes

⚠️ **Important**: These are self-signed certificates intended for development use only. Do not use in production environments.

- Private keys are generated without encryption
- Certificates are not signed by a trusted Certificate Authority
- File permissions are set to `600` for private keys and `644` for certificates

## Troubleshooting

### Permission Errors
If you get permission errors, ensure the output directory is writable:
```bash
chmod 755 /path/to/output/directory
```

### Import Errors
If you get `ModuleNotFoundError: No module named 'cryptography'`:
```bash
pip install cryptography
```

### Browser Still Shows Warnings
Make sure you've properly imported and trusted the certificate in your browser or system certificate store.


## convert crt to pfx
```bash
openssl pkcs12 -export -out dev.test.pfx -inkey dev.test.key -in dev.test.crt
```
