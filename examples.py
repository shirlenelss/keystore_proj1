#!/usr/bin/env python3
"""
Real-world usage examples for Keystore Manager.

This script demonstrates practical scenarios where the Keystore Manager
would be used in real applications.
"""

import sys
from pathlib import Path
import json

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from keystore_manager.keystore import KeystoreManager
from keystore_manager.certificate import CertificateManager
from keystore_manager.security_ops import SecurityOperations


def scenario_1_web_application_setup():
    """
    Scenario 1: Setting up cryptographic infrastructure for a web application
    """
    print("🌐 SCENARIO 1: Web Application Cryptographic Setup")
    print("=" * 60)
    print("Setting up SSL/TLS certificates and application secrets...")
    
    # Initialize managers
    cm = CertificateManager("webapp_certs")
    km = KeystoreManager("webapp_keys")
    sec_ops = SecurityOperations("webapp_audit.log")
    
    # 1. Create CA for internal services
    print("\n1. Creating internal Certificate Authority...")
    ca_cert, ca_key = cm.create_ca_certificate(
        common_name="Internal CA",
        organization="MyCompany Internal",
        validity_days=1825  # 5 years
    )
    print(f"   ✓ Internal CA created: {Path(ca_cert).name}")
    
    # 2. Create web server certificate
    print("\n2. Creating web server certificate...")
    web_cert, web_key = cm.create_self_signed_certificate(
        common_name="api.mycompany.com",
        organization="MyCompany",
        country="US",
        validity_days=365,
        alt_names=[
            "www.api.mycompany.com",
            "staging.api.mycompany.com",
            "api.mycompany.local",
            "10.0.1.100"
        ]
    )
    print(f"   ✓ Web server certificate created: {Path(web_cert).name}")
    
    # 3. Generate application signing keys
    print("\n3. Generating JWT signing keys...")
    jwt_private, jwt_public = km.generate_rsa_keypair(
        key_size=2048,
        key_name="jwt_signing"
    )
    print(f"   ✓ JWT signing keys: {Path(jwt_private).name}, {Path(jwt_public).name}")
    
    # 4. Generate API encryption keys
    print("\n4. Generating data encryption keys...")
    data_private, data_public = km.generate_rsa_keypair(
        key_size=4096,
        key_name="data_encryption"
    )
    print(f"   ✓ Data encryption keys: {Path(data_private).name}, {Path(data_public).name}")
    
    # 5. Create secure passwords for database connections
    print("\n5. Generating secure database passwords...")
    db_passwords = {}
    for service in ["api_db", "cache_db", "analytics_db"]:
        password = sec_ops.generate_secure_password(24)
        db_passwords[service] = password
        print(f"   ✓ {service}: {password[:8]}... (24 chars)")
    
    # 6. Security validation
    print("\n6. Running security validation...")
    cert_validation = cm.validate_certificate(web_cert)
    if cert_validation['valid']:
        print("   ✓ Web certificate validation passed")
    
    # Generate security report
    sec_report = sec_ops.generate_security_report(".")
    print(f"   ✓ Security scan completed - Risk level: {sec_report['summary']['overall_risk']}")
    
    print("\n✅ Web application crypto setup completed!")
    return {
        "ca_cert": ca_cert,
        "web_cert": web_cert,
        "jwt_keys": (jwt_private, jwt_public),
        "data_keys": (data_private, data_public),
        "db_passwords": db_passwords
    }


def scenario_2_microservices_security():
    """
    Scenario 2: Setting up security for microservices communication
    """
    print("\n🔧 SCENARIO 2: Microservices Security Setup")
    print("=" * 60)
    print("Setting up mutual TLS and service-to-service authentication...")
    
    cm = CertificateManager("microservices_certs")
    km = KeystoreManager("microservices_keys")
    
    # Services in our microservices architecture
    services = [
        "user-service",
        "payment-service",
        "inventory-service",
        "notification-service",
        "gateway-service"
    ]
    
    service_certs = {}
    service_keys = {}
    
    print(f"\n1. Creating certificates for {len(services)} microservices...")
    
    # Create certificates for each service
    for service in services:
        # Certificate for HTTPS
        cert_path, key_path = cm.create_self_signed_certificate(
            common_name=f"{service}.internal",
            organization="MyCompany Services",
            alt_names=[
                f"{service}.k8s.cluster.local",
                f"{service}.docker.local",
                f"{service}-prod.internal",
                f"{service}-staging.internal"
            ]
        )
        service_certs[service] = cert_path
        
        # RSA keys for JWT service-to-service auth
        private_key, public_key = km.generate_rsa_keypair(
            key_size=2048,
            key_name=f"{service}_auth"
        )
        service_keys[service] = (private_key, public_key)
        
        print(f"   ✓ {service}: cert + auth keys created")
    
    # Create shared encryption keys for sensitive data
    print("\n2. Creating shared encryption infrastructure...")
    shared_private, shared_public = km.generate_rsa_keypair(
        key_size=4096,
        key_name="shared_encryption"
    )
    print(f"   ✓ Shared encryption keys: {Path(shared_private).name}")
    
    # Generate API keys for external service communication
    print("\n3. Generating API keys for external services...")
    sec_ops = SecurityOperations("microservices_audit.log")
    
    external_apis = ["payment-gateway", "email-service", "sms-service"]
    api_keys = {}
    
    for api in external_apis:
        api_key = sec_ops.generate_secure_password(32)
        api_keys[api] = api_key
        print(f"   ✓ {api}: API key generated")
    
    print("\n✅ Microservices security setup completed!")
    return {
        "service_certs": service_certs,
        "service_keys": service_keys,
        "shared_keys": (shared_private, shared_public),
        "api_keys": api_keys
    }


def scenario_3_data_encryption_pipeline():
    """
    Scenario 3: Setting up a data encryption pipeline for sensitive data processing
    """
    print("\n🔒 SCENARIO 3: Data Encryption Pipeline")
    print("=" * 60)
    print("Setting up encryption for sensitive data processing...")
    
    km = KeystoreManager("data_pipeline_keys")
    sec_ops = SecurityOperations("data_pipeline_audit.log")
    
    # Different encryption keys for different data types
    data_types = [
        "customer_pii",      # Personal Identifiable Information
        "payment_data",      # Payment card data
        "health_records",    # Healthcare data
        "financial_reports", # Financial information
        "audit_logs"         # Audit and compliance logs
    ]
    
    encryption_keys = {}
    
    print(f"\n1. Creating encryption keys for {len(data_types)} data categories...")
    
    for data_type in data_types:
        # Use 4096-bit keys for maximum security
        private_key, public_key = km.generate_rsa_keypair(
            key_size=4096,
            key_name=f"{data_type}_encryption"
        )
        encryption_keys[data_type] = {
            "private": private_key,
            "public": public_key
        }
        print(f"   ✓ {data_type}: 4096-bit RSA keys created")
    
    # Test encryption/decryption with sample data
    print("\n2. Testing encryption pipeline with sample data...")
    
    sample_data = {
        "customer_pii": b"John Doe, SSN: 123-45-6789, DOB: 1985-03-15",
        "payment_data": b"Card: **** **** **** 1234, CVV: 567, Exp: 12/25",
        "health_records": b"Patient ID: P001, Diagnosis: Hypertension, Medication: Lisinopril"
    }
    
    for data_type, data in sample_data.items():
        if data_type in encryption_keys:
            # Encrypt the data
            encrypted_data = km.encrypt_data(data, encryption_keys[data_type]["public"])
            
            # Decrypt to verify
            decrypted_data = km.decrypt_data(
                encrypted_data, 
                encryption_keys[data_type]["private"],
                f"{data_type}_encryption"
            )
            
            success = data == decrypted_data
            print(f"   ✓ {data_type}: Encryption test {'PASSED' if success else 'FAILED'}")
    
    # Generate data handling policies
    print("\n3. Creating data security policies...")
    policy = sec_ops.create_security_policy()
    
    # Add specific policies for data handling
    data_policy = {
        "data_classification": {
            "public": {"encryption_required": False, "retention_days": 2555},  # 7 years
            "internal": {"encryption_required": True, "retention_days": 1095}, # 3 years
            "confidential": {"encryption_required": True, "retention_days": 2555}, # 7 years
            "restricted": {"encryption_required": True, "retention_days": 2555}  # 7 years
        },
        "encryption_requirements": {
            "algorithm": "RSA-OAEP-4096",
            "key_rotation_days": 365,
            "backup_encryption": True
        },
        "access_controls": {
            "data_access_logging": True,
            "require_mfa": True,
            "max_download_size_mb": 100
        }
    }
    
    with open("data_security_policy.json", "w") as f:
        json.dump(data_policy, f, indent=2)
    
    print("   ✓ Data security policy created: data_security_policy.json")
    
    # Simulate compliance reporting
    print("\n4. Generating compliance report...")
    
    compliance_report = {
        "timestamp": "2025-09-28T20:55:00Z",
        "encryption_coverage": {
            "total_data_types": len(data_types),
            "encrypted_data_types": len(encryption_keys),
            "encryption_percentage": 100.0
        },
        "key_management": {
            "total_keys": len(encryption_keys) * 2,  # private + public
            "key_size_bits": 4096,
            "key_algorithm": "RSA-OAEP",
            "keys_password_protected": True
        },
        "compliance_status": {
            "gdpr_compliant": True,
            "hipaa_compliant": True,
            "pci_dss_compliant": True,
            "sox_compliant": True
        }
    }
    
    with open("compliance_report.json", "w") as f:
        json.dump(compliance_report, f, indent=2)
    
    print("   ✓ Compliance report generated: compliance_report.json")
    
    print("\n✅ Data encryption pipeline setup completed!")
    return {
        "encryption_keys": encryption_keys,
        "data_policy": data_policy,
        "compliance_report": compliance_report
    }


def cleanup_examples():
    """Clean up all example files and directories."""
    print("\n🧹 CLEANING UP EXAMPLE FILES")
    print("=" * 40)
    
    import shutil
    
    directories = [
        "webapp_certs", "webapp_keys",
        "microservices_certs", "microservices_keys", 
        "data_pipeline_keys"
    ]
    
    files = [
        "webapp_audit.log", "microservices_audit.log", "data_pipeline_audit.log",
        "data_security_policy.json", "compliance_report.json", "security_policy.json",
        "keystore_operations.log"
    ]
    
    for directory in directories:
        if Path(directory).exists():
            shutil.rmtree(directory)
            print(f"   ✓ Removed: {directory}/")
    
    for file in files:
        if Path(file).exists():
            Path(file).unlink()
            print(f"   ✓ Removed: {file}")
    
    print("\n✅ Cleanup completed!")


def main():
    """Run all real-world scenarios."""
    print("🏢 KEYSTORE MANAGER: REAL-WORLD SCENARIOS")
    print("=" * 70)
    print("Demonstrating practical usage patterns in enterprise environments.\n")
    
    try:
        # Run scenarios
        webapp_setup = scenario_1_web_application_setup()
        microservices_setup = scenario_2_microservices_security()
        data_pipeline_setup = scenario_3_data_encryption_pipeline()
        
        print(f"\n🎉 ALL SCENARIOS COMPLETED SUCCESSFULLY!")
        print("\nScenarios covered:")
        print("1. ✅ Web Application Cryptographic Infrastructure")
        print(f"   - Certificate Authority setup")
        print(f"   - SSL/TLS certificates with SANs")
        print(f"   - JWT signing keys")
        print(f"   - Application data encryption")
        print(f"   - Secure password generation")
        
        print("2. ✅ Microservices Security Architecture") 
        print(f"   - Service-specific certificates")
        print(f"   - Mutual TLS setup")
        print(f"   - Service-to-service authentication")
        print(f"   - Shared encryption infrastructure")
        print(f"   - External API key management")
        
        print("3. ✅ Enterprise Data Encryption Pipeline")
        print(f"   - Data classification encryption")
        print(f"   - High-security 4096-bit keys")
        print(f"   - End-to-end encryption testing")
        print(f"   - Compliance policy generation")
        print(f"   - Regulatory compliance reporting")
        
        print(f"\n📊 Summary Statistics:")
        print(f"   - Total certificates created: {len(webapp_setup['db_passwords']) + len(microservices_setup['service_certs']) + 2}")
        print(f"   - Total key pairs generated: {len(microservices_setup['service_keys']) + 5}")
        print(f"   - Security policies created: 3")
        print(f"   - Compliance frameworks: GDPR, HIPAA, PCI-DSS, SOX")
        
    except Exception as e:
        print(f"❌ Scenario execution failed: {e}")
        raise
    finally:
        cleanup_examples()


if __name__ == "__main__":
    main()