# Certificate Generator Suite

This directory contains Python scripts for generating different types of certificates for local development:

1. **`generate_ssl_cert.py`** - Generates a simple self-signed SSL certificate
2. **`generate_ca_and_cert.py`** - Generates a CA certificate and SSL server certificate (RECOMMENDED)
3. **`generate_code_signing_cert.py`** - Generates a CA certificate and code signing certificate

## Recommended Approach: CA + Server Certificate

The `generate_ca_and_cert.py` script creates:
- A Certificate Authority (CA) certificate that can be imported into browsers
- A server certificate signed by the CA for any specified domain

### Features

- **CA Certificate**: 4096-bit RSA key, valid for 10 years (configurable)
- **Server Certificate**: 2048-bit RSA key, valid for 1 year (configurable)
- **Flexible Configuration**: Command-line arguments for domain, file names, and validity periods
- Supports wildcard domains (e.g., `*.example.com`)
- Includes Subject Alternative Names (SAN) for:
  - Specified domain
  - Base domain (for wildcards)
  - `localhost` (for local testing)
  - `127.0.0.1` (localhost IP)
- Proper file permissions (private keys are owner-readable only)
- Ready-to-use with web servers like nginx

## Requirements

- Python 3.6+
- cryptography library

## Installation

1. Install the required dependency:
```bash
pip install cryptography
```

## Usage

### Generate CA and Server Certificates (Recommended)

#### Basic Usage (Default Values)
```bash
python generate_ca_and_cert.py
```

This will generate four files with default settings:
- `dev-test-ca.crt` - The Certificate Authority certificate (import this into browsers)
- `dev-test-ca.key` - The CA private key (keep secure)
- `dev.test.crt` - The server SSL certificate for `lb.dev.test` (use with nginx)
- `dev.test.key` - The server private key (use with nginx)

#### Advanced Usage with Custom Parameters

**View all available options:**
```bash
python generate_ca_and_cert.py --help
```

**Generate certificates for a custom domain:**
```bash
python generate_ca_and_cert.py --domain "*.example.com"
```

**Generate certificates with custom file names:**
```bash
python generate_ca_and_cert.py --ca-cert my-ca.crt --ca-key my-ca.key --server-cert api.crt --server-key api.key
```

**Full customization example:**
```bash
python generate_ca_and_cert.py \
  --domain "api.mysite.local" \
  --ca-cert custom-ca.crt \
  --ca-key custom-ca.key \
  --server-cert api.crt \
  --server-key api.key \
  --ca-days 7300 \
  --server-days 730 \
  --force
```

#### Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--domain` | `-d` | Domain name for server certificate (supports wildcards) | `lb.dev.test` |
| `--ca-cert` | | CA certificate output file name | `dev-test-ca.crt` |
| `--ca-key` | | CA private key output file name | `dev-test-ca.key` |
| `--server-cert` | | Server certificate output file name | `dev.test.crt` |
| `--server-key` | | Server private key output file name | `dev.test.key` |
| `--ca-days` | | CA certificate validity period in days | `3650` (10 years) |
| `--server-days` | | Server certificate validity period in days | `365` (1 year) |
| `--force` | `-f` | Overwrite existing files without prompting | `false` |

### Generate Simple Self-Signed Certificate

```bash
python generate_ssl_cert.py
```

This will generate two files:
- `dev.test.crt` - The SSL certificate
- `dev.test.key` - The private key

### Generate Code Signing Certificates

```bash
python generate_code_signing_cert.py
```

This will generate four files:
- `code-signing-ca.crt` - The Code Signing CA certificate (import this into system trust store)
- `code-signing-ca.key` - The CA private key (keep secure)
- `code-signing.crt` - The code signing certificate (use for signing code)
- `code-signing.key` - The code signing private key (use for signing code)

## Using with nginx

Add these lines to your nginx server block (adjust file paths and server_name as needed):
```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;  # Match your --domain parameter
    
    ssl_certificate     /path/to/your-server.crt;  # Your --server-cert file
    ssl_certificate_key /path/to/your-server.key;  # Your --server-key file
    
    # Your other configuration...
}
```

**Example for default files:**
```nginx
server {
    listen 443 ssl;
    server_name lb.dev.test *.dev.test;
    
    ssl_certificate     /path/to/dev.test.crt;
    ssl_certificate_key /path/to/dev.test.key;
    
    # Your other configuration...
}
```

## Trusting the Certificate

To avoid browser security warnings, you need to trust the certificate:

### Chrome/Edge (Windows) - Import CA Certificate
1. Double-click your CA certificate file (e.g., `dev-test-ca.crt` or your custom `--ca-cert` file)
2. Click "Install Certificate"
3. Choose "Local Machine" and click "Next"
4. Select "Place all certificates in the following store"
5. Click "Browse" and select "Trusted Root Certification Authorities"
6. Click "Next" and "Finish"
7. Restart your browser

**⚠️ Important:** Import the CA certificate (e.g., `dev-test-ca.crt`), NOT the server certificate (e.g., `dev.test.crt`)

### Firefox (Import CA Certificate)
1. Go to Settings → Privacy & Security → Certificates → View Certificates
2. Click "Import" in the **Authorities** tab
3. Select your CA certificate file (e.g., `dev-test-ca.crt` or your custom `--ca-cert` file)
4. Check "Trust this CA to identify websites"
5. Restart Firefox

**⚠️ Important:** Import the CA certificate, NOT the server certificate

### macOS - Import CA Certificate
```bash
# Replace 'dev-test-ca.crt' with your actual CA certificate file name
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain dev-test-ca.crt
```

### Linux - Import CA Certificate
```bash
# Replace 'dev-test-ca.crt' with your actual CA certificate file name
sudo cp dev-test-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

## Security Notice

⚠️ **This certificate is for development use only!** 

- It's self-signed and not issued by a trusted Certificate Authority
- Never use self-signed certificates in production
- The private key is generated without a passphrase for convenience

## Customization

The `generate_ca_and_cert.py` script now supports full customization through command-line arguments:

- **Domain name**: Use `--domain` to specify any domain (supports wildcards)
- **File names**: Use `--ca-cert`, `--ca-key`, `--server-cert`, `--server-key` to customize output files
- **Validity periods**: Use `--ca-days` and `--server-days` to set certificate lifetimes
- **Certificate subject information**: Can be modified by editing the script's certificate subject fields

**No need to edit the script directly** - all common customizations are available via command-line options!

## Important Notes

**For Firefox Certificate Import Issues:**

If you're getting "This is not a certificate authority certificate" error in Firefox, you're trying to import the wrong file:

- ❌ **DON'T import**: Server certificate files (e.g., `dev.test.crt`, or your custom `--server-cert` file)
- ✅ **DO import**: CA certificate files (e.g., `dev-test-ca.crt`, or your custom `--ca-cert` file)

The CA certificate is what you import into your browser's trusted authorities. The server certificate is used by nginx/web servers.

**Certificate Chains:**

**SSL Certificates (generate_ca_and_cert.py):**
- CA Certificate (e.g., `dev-test-ca.crt` or your custom `--ca-cert` file) → Certificate Authority (import into browser)
- Server Certificate (e.g., `dev.test.crt` or your custom `--server-cert` file) → Server certificate signed by the CA (use with nginx)

**Code Signing Certificates (generate_code_signing_cert.py):**
- `code-signing-ca.crt` → Code Signing CA (import into system trust store)
- `code-signing.crt` → Code signing certificate (use to sign executables, scripts, etc.)

## Code Signing Usage Examples

After generating and importing the CA certificate, you can use the code signing certificate to sign various types of code:

### PowerShell Scripts (Windows)
```powershell
# Sign a PowerShell script
Set-AuthenticodeSignature -FilePath "script.ps1" -Certificate (Get-PfxCertificate "code-signing.crt")
```

### Executables with SignTool (Windows)
```cmd
# Sign an executable
signtool sign /f "code-signing.crt" /p "" /t http://timestamp.digicert.com "executable.exe"
```

### Java JAR Files
```bash
# Convert certificate to PKCS#12 format first
openssl pkcs12 -export -in code-signing.crt -inkey code-signing.key -out code-signing.p12

# Sign JAR file
jarsigner -keystore code-signing.p12 -storetype PKCS12 myapp.jar "1"
```

### macOS Applications
```bash
# Import certificate to keychain first, then sign
codesign -s "Dev Code Signing Certificate" -v myapp.app
```