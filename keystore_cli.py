#!/usr/bin/env python3
"""
Command-line interface for the Keystore Manager.

This CLI provides easy access to keystore, certificate, and security operations.
"""

import click
import json
import sys
from pathlib import Path

# Add the src directory to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent / "src"))

from keystore_manager.keystore import KeystoreManager
from keystore_manager.certificate import CertificateManager
from keystore_manager.security_ops import SecurityOperations


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Keystore Manager - Practice tool for keystore, certificates, and secOps."""
    pass


@cli.group()
def keystore():
    """Key management operations."""
    pass


@cli.group()
def certificate():
    """Certificate management operations."""
    pass


@cli.group()
def security():
    """Security operations and analysis."""
    pass


# Keystore commands
@keystore.command()
@click.option('--key-size', default=2048, help='RSA key size (default: 2048)')
@click.option('--key-name', default='default', help='Key pair name (default: default)')
@click.option('--keystore-path', default='keystore', help='Keystore directory path')
def generate_key(key_size, key_name, keystore_path):
    """Generate a new RSA key pair."""
    try:
        km = KeystoreManager(keystore_path)
        private_key_path, public_key_path = km.generate_rsa_keypair(key_size, key_name)
        
        click.echo(f"✓ Generated RSA key pair '{key_name}' ({key_size} bits)")
        click.echo(f"  Private key: {private_key_path}")
        click.echo(f"  Public key: {public_key_path}")
        
    except Exception as e:
        click.echo(f"✗ Error generating key pair: {e}", err=True)
        sys.exit(1)


@keystore.command()
@click.option('--keystore-path', default='keystore', help='Keystore directory path')
def list_keys(keystore_path):
    """List all keys in the keystore."""
    try:
        km = KeystoreManager(keystore_path)
        keys = km.list_keys()
        
        if not keys:
            click.echo("No keys found in keystore.")
            return
        
        click.echo("Keys in keystore:")
        for key_name, key_info in keys.items():
            click.echo(f"  📁 {key_name}")
            click.echo(f"    Private: {key_info['private_key']}")
            click.echo(f"    Public:  {key_info['public_key']}")
            click.echo(f"    Created: {key_info['created']}")
            
    except Exception as e:
        click.echo(f"✗ Error listing keys: {e}", err=True)
        sys.exit(1)


@keystore.command()
@click.argument('key_name')
@click.option('--keystore-path', default='keystore', help='Keystore directory path')
@click.confirmation_option(prompt='Are you sure you want to delete this key pair?')
def delete_key(key_name, keystore_path):
    """Delete a key pair from the keystore."""
    try:
        km = KeystoreManager(keystore_path)
        success = km.delete_key(key_name)
        
        if success:
            click.echo(f"✓ Deleted key pair: {key_name}")
        else:
            click.echo(f"✗ Key pair not found: {key_name}")
            
    except Exception as e:
        click.echo(f"✗ Error deleting key pair: {e}", err=True)
        sys.exit(1)


@keystore.command()
@click.argument('input_file')
@click.argument('public_key_path')
@click.option('--output', '-o', help='Output file for encrypted data')
def encrypt(input_file, public_key_path, output):
    """Encrypt a file using a public key."""
    try:
        km = KeystoreManager()
        
        # Read input file
        with open(input_file, 'rb') as f:
            data = f.read()
        
        encrypted_data = km.encrypt_data(data, public_key_path)
        
        # Write encrypted data
        output_file = output or f"{input_file}.encrypted"
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
        
        click.echo(f"✓ Encrypted {input_file} -> {output_file}")
        
    except Exception as e:
        click.echo(f"✗ Error encrypting file: {e}", err=True)
        sys.exit(1)


@keystore.command()
@click.argument('input_file')
@click.argument('private_key_path')
@click.option('--key-name', default='default', help='Key name for password lookup')
@click.option('--output', '-o', help='Output file for decrypted data')
def decrypt(input_file, private_key_path, key_name, output):
    """Decrypt a file using a private key."""
    try:
        km = KeystoreManager()
        
        # Read encrypted file
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = km.decrypt_data(encrypted_data, private_key_path, key_name)
        
        # Write decrypted data
        output_file = output or input_file.replace('.encrypted', '.decrypted')
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        click.echo(f"✓ Decrypted {input_file} -> {output_file}")
        
    except Exception as e:
        click.echo(f"✗ Error decrypting file: {e}", err=True)
        sys.exit(1)


# Certificate commands
@certificate.command()
@click.option('--common-name', default='localhost', help='Certificate common name')
@click.option('--organization', default='Keystore Practice', help='Organization name')
@click.option('--country', default='US', help='Country code')
@click.option('--validity-days', default=365, help='Certificate validity in days')
@click.option('--alt-names', help='Comma-separated alternative names')
@click.option('--cert-path', default='certificates', help='Certificate directory path')
def create_self_signed(common_name, organization, country, validity_days, alt_names, cert_path):
    """Create a self-signed certificate."""
    try:
        cm = CertificateManager(cert_path)
        
        alt_names_list = None
        if alt_names:
            alt_names_list = [name.strip() for name in alt_names.split(',')]
        
        cert_file, key_file = cm.create_self_signed_certificate(
            common_name=common_name,
            organization=organization,
            country=country,
            validity_days=validity_days,
            alt_names=alt_names_list
        )
        
        click.echo(f"✓ Created self-signed certificate for '{common_name}'")
        click.echo(f"  Certificate: {cert_file}")
        click.echo(f"  Private key: {key_file}")
        
    except Exception as e:
        click.echo(f"✗ Error creating certificate: {e}", err=True)
        sys.exit(1)


@certificate.command()
@click.option('--common-name', default='Practice CA', help='CA common name')
@click.option('--organization', default='Keystore Practice CA', help='CA organization')
@click.option('--country', default='US', help='Country code')
@click.option('--validity-days', default=3650, help='CA validity in days')
@click.option('--cert-path', default='certificates', help='Certificate directory path')
def create_ca(common_name, organization, country, validity_days, cert_path):
    """Create a Certificate Authority (CA) certificate."""
    try:
        cm = CertificateManager(cert_path)
        
        cert_file, key_file = cm.create_ca_certificate(
            common_name=common_name,
            organization=organization,
            country=country,
            validity_days=validity_days
        )
        
        click.echo(f"✓ Created CA certificate '{common_name}'")
        click.echo(f"  Certificate: {cert_file}")
        click.echo(f"  Private key: {key_file}")
        
    except Exception as e:
        click.echo(f"✗ Error creating CA certificate: {e}", err=True)
        sys.exit(1)


@certificate.command()
@click.argument('cert_path')
@click.option('--ca-cert', help='CA certificate for chain validation')
def validate(cert_path, ca_cert):
    """Validate a certificate."""
    try:
        cm = CertificateManager()
        result = cm.validate_certificate(cert_path, ca_cert)
        
        if result['valid']:
            click.echo(f"✓ Certificate is valid")
        else:
            click.echo(f"✗ Certificate is invalid")
        
        if result['errors']:
            click.echo("Errors:")
            for error in result['errors']:
                click.echo(f"  • {error}")
        
        if result['warnings']:
            click.echo("Warnings:")
            for warning in result['warnings']:
                click.echo(f"  ⚠ {warning}")
        
        click.echo(f"Certificate Information:")
        info = result['info']
        click.echo(f"  Subject: {info.get('subject', 'N/A')}")
        click.echo(f"  Issuer: {info.get('issuer', 'N/A')}")
        click.echo(f"  Valid from: {info.get('not_valid_before', 'N/A')}")
        click.echo(f"  Valid until: {info.get('not_valid_after', 'N/A')}")
        click.echo(f"  Key size: {info.get('key_size', 'N/A')}")
        
    except Exception as e:
        click.echo(f"✗ Error validating certificate: {e}", err=True)
        sys.exit(1)


@certificate.command()
@click.option('--cert-path', default='certificates', help='Certificate directory path')
def list_certs(cert_path):
    """List all certificates."""
    try:
        cm = CertificateManager(cert_path)
        certificates = cm.list_certificates()
        
        if not certificates:
            click.echo("No certificates found.")
            return
        
        click.echo("Certificates:")
        for cert_name, cert_info in certificates.items():
            if 'error' in cert_info:
                click.echo(f"  ❌ {cert_name}: {cert_info['error']}")
                continue
                
            status = "🔒 CA" if cert_info['is_ca'] else "📄"
            click.echo(f"  {status} {cert_name}")
            click.echo(f"    Subject: {cert_info['subject']}")
            click.echo(f"    Valid: {cert_info['not_valid_before']} to {cert_info['not_valid_after']}")
            
    except Exception as e:
        click.echo(f"✗ Error listing certificates: {e}", err=True)
        sys.exit(1)


# Security commands
@security.command()
@click.option('--length', default=16, help='Password length (minimum 12)')
def generate_password(length):
    """Generate a secure password."""
    try:
        sec_ops = SecurityOperations()
        password = sec_ops.generate_secure_password(length)
        
        click.echo(f"Generated secure password: {password}")
        
        # Validate the generated password
        validation = sec_ops.validate_password(password)
        click.echo(f"Password strength score: {validation['score']}/{validation['max_score']}")
        
    except Exception as e:
        click.echo(f"✗ Error generating password: {e}", err=True)
        sys.exit(1)


@security.command()
@click.argument('password')
def validate_password(password):
    """Validate a password against security policy."""
    try:
        sec_ops = SecurityOperations()
        result = sec_ops.validate_password(password)
        
        if result['valid']:
            click.echo("✓ Password meets security requirements")
        else:
            click.echo("✗ Password does not meet security requirements")
        
        click.echo(f"Strength score: {result['score']}/{result['max_score']}")
        
        if result['issues']:
            click.echo("Issues:")
            for issue in result['issues']:
                click.echo(f"  • {issue}")
        
        if result['recommendations']:
            click.echo("Recommendations:")
            for rec in result['recommendations']:
                click.echo(f"  💡 {rec}")
                
    except Exception as e:
        click.echo(f"✗ Error validating password: {e}", err=True)
        sys.exit(1)


@security.command()
@click.argument('directory')
@click.option('--output', '-o', help='Output file for findings')
def scan_secrets(directory, output):
    """Scan directory for potential secrets."""
    try:
        sec_ops = SecurityOperations()
        findings = sec_ops.scan_for_secrets(directory)
        
        if not findings:
            click.echo("✓ No potential secrets found")
            return
        
        click.echo(f"⚠ Found potential secrets in {len(findings)} files:")
        
        total_findings = 0
        for file_path, file_findings in findings.items():
            click.echo(f"\n  📁 {file_path}")
            for finding in file_findings:
                total_findings += 1
                click.echo(f"    Line {finding['line']}: {finding['type']}")
                click.echo(f"      {finding['match']}")
        
        click.echo(f"\nTotal findings: {total_findings}")
        
        if output:
            with open(output, 'w') as f:
                json.dump(findings, f, indent=2)
            click.echo(f"Detailed findings saved to: {output}")
            
    except Exception as e:
        click.echo(f"✗ Error scanning for secrets: {e}", err=True)
        sys.exit(1)


@security.command()
@click.argument('directory')
@click.option('--output', '-o', help='Output file for report')
def security_report(directory, output):
    """Generate comprehensive security report."""
    try:
        sec_ops = SecurityOperations()
        report = sec_ops.generate_security_report(directory)
        
        if 'error' in report:
            click.echo(f"✗ Error generating report: {report['error']}")
            return
        
        summary = report['summary']
        click.echo("Security Report Summary:")
        click.echo(f"  Files scanned: {summary['total_files_scanned']}")
        click.echo(f"  Secret findings: {summary['secret_findings']}")
        click.echo(f"  Permission issues: {summary['permission_issues']}")
        click.echo(f"  High severity: {summary['high_severity_issues']}")
        click.echo(f"  Overall risk: {summary['overall_risk'].upper()}")
        click.echo(f"  Scan duration: {summary['scan_duration_seconds']:.2f}s")
        
        if output:
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)
            click.echo(f"\nDetailed report saved to: {output}")
            
    except Exception as e:
        click.echo(f"✗ Error generating security report: {e}", err=True)
        sys.exit(1)


@security.command()
@click.option('--output', default='security_policy.json', help='Output file for policy')
def create_policy(output):
    """Create security policy configuration."""
    try:
        sec_ops = SecurityOperations()
        policy = sec_ops.create_security_policy()
        
        click.echo(f"✓ Created security policy: {output}")
        click.echo("Policy includes:")
        click.echo("  • Password requirements")
        click.echo("  • File permission standards")
        click.echo("  • Encryption standards")
        click.echo("  • Audit requirements")
        click.echo("  • Certificate policies")
        
    except Exception as e:
        click.echo(f"✗ Error creating security policy: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()