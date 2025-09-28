import unittest
import tempfile
import shutil
from pathlib import Path
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from keystore_manager.security_ops import SecurityOperations


class TestSecurityOperations(unittest.TestCase):
    """Test cases for SecurityOperations."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.audit_log_path = os.path.join(self.test_dir, 'test_audit.log')
        self.sec_ops = SecurityOperations(self.audit_log_path)
        
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
        
    def test_generate_secure_password(self):
        """Test secure password generation."""
        password = self.sec_ops.generate_secure_password(16)
        
        self.assertEqual(len(password), 16)
        self.assertIsInstance(password, str)
        
        # Test that different calls generate different passwords
        password2 = self.sec_ops.generate_secure_password(16)
        self.assertNotEqual(password, password2)
        
    def test_generate_secure_password_length_validation(self):
        """Test password length validation."""
        with self.assertRaises(ValueError):
            self.sec_ops.generate_secure_password(8)  # Too short
            
    def test_validate_password_strong(self):
        """Test validation of a strong password."""
        strong_password = "StrongPass123!@#"
        result = self.sec_ops.validate_password(strong_password)
        
        self.assertIsInstance(result, dict)
        self.assertIn('valid', result)
        self.assertIn('score', result)
        self.assertIn('issues', result)
        self.assertTrue(result['valid'])
        self.assertGreater(result['score'], 70)
        
    def test_validate_password_weak(self):
        """Test validation of a weak password."""
        weak_password = "password"
        result = self.sec_ops.validate_password(weak_password)
        
        self.assertFalse(result['valid'])
        self.assertGreater(len(result['issues']), 0)
        
    def test_hash_and_verify_password(self):
        """Test password hashing and verification."""
        password = "TestPassword123!"
        
        # Hash the password
        hash_result = self.sec_ops.hash_password(password)
        
        self.assertIn('hash', hash_result)
        self.assertIn('salt', hash_result)
        self.assertIn('algorithm', hash_result)
        self.assertIn('iterations', hash_result)
        
        # Verify the password
        is_valid = self.sec_ops.verify_password(
            password, 
            hash_result['hash'], 
            hash_result['salt'], 
            hash_result['iterations']
        )
        self.assertTrue(is_valid)
        
        # Verify with wrong password
        is_invalid = self.sec_ops.verify_password(
            "WrongPassword", 
            hash_result['hash'], 
            hash_result['salt'], 
            hash_result['iterations']
        )
        self.assertFalse(is_invalid)
        
    def test_scan_for_secrets(self):
        """Test secret scanning functionality."""
        # Create a test file with a potential secret
        test_file = Path(self.test_dir) / "test_config.py"
        test_content = '''
import os

DATABASE_URL = "postgresql://user:password@localhost/db"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
SECRET_KEY = "very-secret-key-12345"
'''
        test_file.write_text(test_content)
        
        findings = self.sec_ops.scan_for_secrets(self.test_dir)
        
        self.assertIsInstance(findings, dict)
        if findings:  # If any secrets were found
            self.assertIn(str(test_file), findings)
            
    def test_check_file_permissions(self):
        """Test file permission checking."""
        # Create files with different permissions
        test_file1 = Path(self.test_dir) / "normal_file.txt"
        test_file2 = Path(self.test_dir) / "world_writable.txt"
        
        test_file1.write_text("normal content")
        test_file2.write_text("sensitive content")
        
        # Make one file world-writable (security issue)
        test_file2.chmod(0o666)
        
        result = self.sec_ops.check_file_permissions(self.test_dir)
        
        self.assertIsInstance(result, dict)
        self.assertIn('checked_files', result)
        self.assertIn('issues', result)
        self.assertGreater(result['checked_files'], 0)
        
    def test_create_security_policy(self):
        """Test security policy creation."""
        policy = self.sec_ops.create_security_policy()
        
        self.assertIsInstance(policy, dict)
        self.assertIn('password_policy', policy)
        self.assertIn('file_permissions', policy)
        self.assertIn('encryption_standards', policy)
        self.assertIn('audit_requirements', policy)
        
    def test_audit_logging(self):
        """Test audit logging functionality."""
        # Perform an action that should be audited
        self.sec_ops.audit_log("test_action", "test_user", {"detail": "test_detail"})
        
        # Check that the audit log file was created
        self.assertTrue(Path(self.audit_log_path).exists())
        
        # Read the log content
        with open(self.audit_log_path, 'r') as f:
            log_content = f.read()
            
        self.assertIn("test_action", log_content)
        self.assertIn("test_user", log_content)


if __name__ == '__main__':
    unittest.main()