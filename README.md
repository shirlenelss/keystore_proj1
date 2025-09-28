# Keystore Manager - Practice Project

A comprehensive practice project for keystore management, X.509 certificates, and security operations (SecOps). This project demonstrates cryptographic best practices, secure key management, certificate handling, and security monitoring.

## Features

### 🔐 Keystore Management
- RSA key pair generation (2048, 4096 bits)
- Secure key storage with password protection
- Hybrid encryption for large data (AES + RSA)
- Secure key deletion with overwriting
- Key rotation and management

### 📜 Certificate Management  
- Self-signed certificate creation
- Certificate Authority (CA) setup
- Certificate signing requests (CSR)
- Certificate chain validation
- X.509 certificate parsing and validation
- Subject Alternative Names (SAN) support

### 🛡️ Security Operations (SecOps)
- Password policy enforcement
- Secure password generation
- Secret scanning in codebases
- File permission auditing
- Security compliance reporting
- Audit logging for all operations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/shirlenelss/keystore_proj1.git
cd keystore_proj1
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make the CLI executable:
```bash
chmod +x keystore_cli.py
```

## Quick Start

### Generate a Key Pair
```bash
python keystore_cli.py keystore generate-key --key-name mykey --key-size 2048
```

### Create a Self-Signed Certificate
```bash
python keystore_cli.py certificate create-self-signed \
    --common-name localhost \
    --organization "My Company" \
    --validity-days 365
```

### Generate a Secure Password
```bash
python keystore_cli.py security generate-password --length 16
```

### Scan for Secrets
```bash
python keystore_cli.py security scan-secrets . --output secrets_report.json
```

## CLI Usage

The project includes a comprehensive command-line interface:

### Keystore Commands
- `generate-key` - Generate RSA key pairs
- `list-keys` - List all keys in keystore
- `delete-key` - Securely delete key pairs
- `encrypt` - Encrypt files with public keys
- `decrypt` - Decrypt files with private keys

### Certificate Commands
- `create-self-signed` - Create self-signed certificates
- `create-ca` - Create Certificate Authority
- `validate` - Validate certificates
- `list-certs` - List all certificates

### Security Commands
- `generate-password` - Generate secure passwords
- `validate-password` - Check password strength
- `scan-secrets` - Scan for potential secrets
- `security-report` - Generate comprehensive security report
- `create-policy` - Create security policy template

## Project Structure

```
keystore_proj1/
├── src/keystore_manager/          # Main modules
│   ├── __init__.py               # Package initialization
│   ├── keystore.py               # Key management
│   ├── certificate.py            # Certificate operations
│   └── security_ops.py           # Security operations
├── tests/                        # Unit tests
│   ├── test_keystore.py
│   ├── test_certificate.py
│   └── test_security_ops.py
├── config/                       # Configuration files
│   └── keystore_config.yml
├── docs/                         # Documentation
├── keystore_cli.py               # Command-line interface
├── requirements.txt              # Dependencies
├── .gitignore                    # Git ignore patterns
└── README.md                     # This file
```

## Security Best Practices Demonstrated

### Key Management
- ✅ Minimum 2048-bit RSA keys
- ✅ Password-protected private keys
- ✅ Secure key storage with proper permissions (600)
- ✅ Secure deletion with overwriting
- ✅ Hybrid encryption for large data

### Certificate Management
- ✅ Proper certificate validation
- ✅ Certificate chain verification
- ✅ Appropriate certificate extensions
- ✅ SAN (Subject Alternative Names) support
- ✅ Certificate expiration monitoring

### Security Operations
- ✅ Strong password policies
- ✅ PBKDF2 password hashing
- ✅ Secret scanning
- ✅ File permission auditing
- ✅ Comprehensive audit logging
- ✅ Security compliance reporting

## Running Tests

Execute the test suite:

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m unittest tests/test_keystore.py

# Run with coverage
pip install coverage
coverage run -m unittest discover tests/
coverage report
```

## Configuration

The project uses YAML configuration files. See `config/keystore_config.yml` for available options:

- Keystore settings (paths, key sizes)
- Certificate policies (validity, extensions)
- Security policies (password rules, encryption standards)
- File permissions
- Audit requirements

## Security Considerations

⚠️ **Important**: This is a practice/learning project. For production use:

1. Use a proper Hardware Security Module (HSM)
2. Implement proper secret management (e.g., HashiCorp Vault)
3. Use encrypted storage for private keys
4. Implement proper access controls and authentication
5. Regular security audits and penetration testing
6. Compliance with relevant standards (FIPS 140-2, Common Criteria)

## Learning Objectives

This project covers:

1. **Cryptographic Concepts**
   - Symmetric vs. asymmetric encryption
   - Key derivation functions
   - Digital signatures
   - Certificate chains and PKI

2. **Security Operations**
   - Threat modeling
   - Vulnerability scanning
   - Incident response preparation
   - Compliance monitoring

3. **Best Practices**
   - Secure coding practices
   - Defense in depth
   - Least privilege principle
   - Audit and monitoring

## Contributing

This is a practice project, but contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is for educational purposes. Use at your own risk.

## Resources

- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [RFC 5280 - X.509 Certificate Profile](https://tools.ietf.org/html/rfc5280)
- [Python Cryptography Library](https://cryptography.io/)

---

**Disclaimer**: This project is for educational and practice purposes only. Do not use in production without proper security review and hardening.