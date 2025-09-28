#!/usr/bin/env python3
"""
Example demonstration of Keystore Manager functionality.

This script demonstrates various operations for learning purposes.
"""

import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from keystore_manager.keystore import KeystoreManager
from keystore_manager.certificate import CertificateManager
from keystore_manager.security_ops import SecurityOperations
import tempfile
import shutil


def demo_keystore_operations():
    """Demonstrate keystore operations."""
    print("🔐 KEYSTORE OPERATIONS DEMO")
    print("=" * 40)
    
    # Create temporary directory for demo
    demo_dir = "demo_keystore"
    km = KeystoreManager(demo_dir)
    
    # Generate keys
    print("1. Generating RSA key pair...")
    private_key, public_key = km.generate_rsa_keypair(key_size=2048, key_name="demo_key")
    print(f"   ✓ Private key: {private_key}")
    print(f"   ✓ Public key: {public_key}")
    
    # List keys
    print("\n2. Listing all keys...")
    keys = km.list_keys()
    for key_name, key_info in keys.items():
        print(f"   📁 {key_name}: {key_info['created']}")
    
    # Encrypt/Decrypt data
    print("\n3. Testing encryption/decryption...")
    test_data = b"Hello, this is sensitive data for encryption demo!"
    
    encrypted_data = km.encrypt_data(test_data, public_key)
    print(f"   ✓ Data encrypted ({len(encrypted_data)} bytes)")
    
    decrypted_data = km.decrypt_data(encrypted_data, private_key, "demo_key")
    print(f"   ✓ Data decrypted: {decrypted_data.decode()}")
    
    print("\n✅ Keystore demo completed!\n")


def demo_certificate_operations():
    """Demonstrate certificate operations."""
    print("📜 CERTIFICATE OPERATIONS DEMO")
    print("=" * 40)
    
    demo_dir = "demo_certificates"
    cm = CertificateManager(demo_dir)
    
    # Create self-signed certificate
    print("1. Creating self-signed certificate...")
    cert_path, key_path = cm.create_self_signed_certificate(
        common_name="demo.example.com",
        organization="Demo Organization",
        country="US",
        validity_days=30,
        alt_names=["www.demo.example.com", "api.demo.example.com", "192.168.1.100"]
    )
    print(f"   ✓ Certificate: {cert_path}")
    print(f"   ✓ Private key: {key_path}")
    
    # Create CA certificate
    print("\n2. Creating Certificate Authority...")
    ca_cert, ca_key = cm.create_ca_certificate(
        common_name="Demo CA",
        organization="Demo Certificate Authority",
        validity_days=365
    )
    print(f"   ✓ CA Certificate: {ca_cert}")
    print(f"   ✓ CA Private key: {ca_key}")
    
    # Validate certificate
    print("\n3. Validating certificate...")
    validation_result = cm.validate_certificate(cert_path)
    print(f"   ✓ Certificate valid: {validation_result['valid']}")
    print(f"   ✓ Subject: {validation_result['info']['subject']}")
    print(f"   ✓ Valid until: {validation_result['info']['not_valid_after']}")
    
    if validation_result['warnings']:
        for warning in validation_result['warnings']:
            print(f"   ⚠ Warning: {warning}")
    
    # List certificates
    print("\n4. Listing all certificates...")
    certificates = cm.list_certificates()
    for cert_name, cert_info in certificates.items():
        if 'error' not in cert_info:
            ca_indicator = "🔒 CA" if cert_info['is_ca'] else "📄"
            print(f"   {ca_indicator} {cert_name}")
            print(f"     Subject: {cert_info['subject']}")
    
    print("\n✅ Certificate demo completed!\n")


def demo_security_operations():
    """Demonstrate security operations."""
    print("🛡️ SECURITY OPERATIONS DEMO")
    print("=" * 40)
    
    sec_ops = SecurityOperations("demo_audit.log")
    
    # Password generation and validation
    print("1. Generating secure password...")
    password = sec_ops.generate_secure_password(16)
    print(f"   ✓ Generated password: {password}")
    
    print("\n2. Validating password strength...")
    validation = sec_ops.validate_password(password)
    print(f"   ✓ Password valid: {validation['valid']}")
    print(f"   ✓ Strength score: {validation['score']}/100")
    
    # Test with weak password
    weak_password = "password123"
    weak_validation = sec_ops.validate_password(weak_password)
    print(f"\n   Testing weak password: '{weak_password}'")
    print(f"   ✗ Password valid: {weak_validation['valid']}")
    print(f"   ✗ Strength score: {weak_validation['score']}/100")
    for issue in weak_validation['issues'][:2]:  # Show first 2 issues
        print(f"     • {issue}")
    
    # Password hashing
    print("\n3. Demonstrating secure password hashing...")
    hash_result = sec_ops.hash_password("SecurePassword123!")
    print(f"   ✓ Password hashed with {hash_result['algorithm']}")
    print(f"   ✓ Using {hash_result['iterations']} iterations")
    
    # Verify password
    is_valid = sec_ops.verify_password(
        "SecurePassword123!", 
        hash_result['hash'], 
        hash_result['salt'],
        hash_result['iterations']
    )
    print(f"   ✓ Password verification: {is_valid}")
    
    # Create a test file with potential secrets
    print("\n4. Creating test file with potential secrets...")
    test_file = Path("demo_config.py")
    test_content = '''
# Demo configuration file with potential secrets
DATABASE_URL = "postgresql://user:secret_password@localhost:5432/mydb"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890"
SECRET_TOKEN = "abc123def456ghi789"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# This is fine
DEBUG = True
PORT = 8080
    '''
    test_file.write_text(test_content)
    
    # Scan for secrets
    print("5. Scanning for potential secrets...")
    findings = sec_ops.scan_for_secrets(".")
    if findings:
        total_findings = sum(len(f) for f in findings.values())
        print(f"   ⚠ Found {total_findings} potential secrets in {len(findings)} files")
        for file_path, file_findings in list(findings.items())[:1]:  # Show first file
            print(f"     📁 {Path(file_path).name}")
            for finding in file_findings[:2]:  # Show first 2 findings
                print(f"       Line {finding['line']}: {finding['type']}")
    else:
        print("   ✓ No potential secrets found")
    
    # Generate security policy
    print("\n6. Creating security policy...")
    policy = sec_ops.create_security_policy()
    print(f"   ✓ Security policy created with {len(policy)} sections")
    print("   ✓ Policy includes password rules, file permissions, encryption standards")
    
    # Clean up test file
    if test_file.exists():
        test_file.unlink()
    
    print("\n✅ Security operations demo completed!\n")


def cleanup_demo():
    """Clean up demo directories."""
    print("🧹 CLEANUP")
    print("=" * 40)
    
    directories_to_remove = ["demo_keystore", "demo_certificates"]
    files_to_remove = ["demo_audit.log", "security_policy.json", "keystore_operations.log"]
    
    for directory in directories_to_remove:
        if Path(directory).exists():
            shutil.rmtree(directory)
            print(f"   ✓ Removed directory: {directory}")
    
    for file in files_to_remove:
        if Path(file).exists():
            Path(file).unlink()
            print(f"   ✓ Removed file: {file}")
    
    print("\n✅ Cleanup completed!\n")


def main():
    """Run all demonstrations."""
    print("🎯 KEYSTORE MANAGER DEMONSTRATION")
    print("=" * 50)
    print("This demo showcases keystore, certificate, and security operations.")
    print("All operations use secure practices and demonstrate best practices.\n")
    
    try:
        demo_keystore_operations()
        demo_certificate_operations()
        demo_security_operations()
        
        print("🎉 ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY!")
        print("\nThis demo covered:")
        print("• RSA key pair generation and management")
        print("• Hybrid encryption for large data")
        print("• Self-signed and CA certificate creation")
        print("• Certificate validation and chain management")
        print("• Secure password generation and validation")
        print("• Password hashing with PBKDF2")
        print("• Secret scanning in source code")
        print("• Security policy creation")
        print("• Comprehensive audit logging")
        
    except Exception as e:
        print(f"❌ Demo failed with error: {e}")
        raise
    finally:
        cleanup_demo()


if __name__ == "__main__":
    main()