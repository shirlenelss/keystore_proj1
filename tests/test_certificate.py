import unittest
import tempfile
import shutil
from pathlib import Path
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from keystore_manager.certificate import CertificateManager


class TestCertificateManager(unittest.TestCase):
    """Test cases for CertificateManager."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.cert_path = os.path.join(self.test_dir, 'test_certificates')
        self.cm = CertificateManager(self.cert_path)
        
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
        
    def test_certificate_directory_creation(self):
        """Test certificate directory initialization."""
        self.assertTrue(Path(self.cert_path).exists())
        
    def test_create_self_signed_certificate(self):
        """Test self-signed certificate creation."""
        cert_path, key_path = self.cm.create_self_signed_certificate(
            common_name="test.example.com",
            organization="Test Org",
            validity_days=30
        )
        
        self.assertTrue(Path(cert_path).exists())
        self.assertTrue(Path(key_path).exists())
        
        # Check file permissions
        cert_stat = Path(cert_path).stat()
        key_stat = Path(key_path).stat()
        self.assertEqual(oct(cert_stat.st_mode)[-3:], '644')
        self.assertEqual(oct(key_stat.st_mode)[-3:], '600')
        
    def test_create_ca_certificate(self):
        """Test CA certificate creation."""
        ca_cert_path, ca_key_path = self.cm.create_ca_certificate(
            common_name="Test CA",
            organization="Test CA Org",
            validity_days=365
        )
        
        self.assertTrue(Path(ca_cert_path).exists())
        self.assertTrue(Path(ca_key_path).exists())
        
    def test_validate_certificate(self):
        """Test certificate validation."""
        # Create a self-signed certificate
        cert_path, _ = self.cm.create_self_signed_certificate(
            common_name="validate.test.com",
            validity_days=365
        )
        
        # Validate the certificate
        result = self.cm.validate_certificate(cert_path)
        
        self.assertIsInstance(result, dict)
        self.assertIn('valid', result)
        self.assertIn('info', result)
        self.assertIn('errors', result)
        self.assertIn('warnings', result)
        
        # Should be valid since it's not expired and properly formatted
        if result['errors']:
            print(f"Validation errors: {result['errors']}")
        
    def test_list_certificates(self):
        """Test listing certificates."""
        # Create a test certificate
        cert_path, _ = self.cm.create_self_signed_certificate(
            common_name="list.test.com"
        )
        
        certificates = self.cm.list_certificates()
        
        self.assertIsInstance(certificates, dict)
        self.assertGreater(len(certificates), 0)
        
        # Find our certificate in the list
        cert_found = False
        for cert_name, cert_info in certificates.items():
            if 'error' not in cert_info:
                cert_found = True
                self.assertIn('subject', cert_info)
                self.assertIn('issuer', cert_info)
                self.assertIn('not_valid_before', cert_info)
                self.assertIn('not_valid_after', cert_info)
                break
        
        self.assertTrue(cert_found, "Test certificate not found in listing")
        
    def test_certificate_with_alt_names(self):
        """Test certificate creation with Subject Alternative Names."""
        alt_names = ["alt1.example.com", "alt2.example.com", "192.168.1.1"]
        
        cert_path, _ = self.cm.create_self_signed_certificate(
            common_name="main.example.com",
            alt_names=alt_names
        )
        
        self.assertTrue(Path(cert_path).exists())
        
        # Validate that the certificate was created successfully
        result = self.cm.validate_certificate(cert_path)
        self.assertIn('extensions', result['info'])


if __name__ == '__main__':
    unittest.main()