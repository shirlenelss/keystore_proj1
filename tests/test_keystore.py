import unittest
import tempfile
import shutil
from pathlib import Path
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from keystore_manager.keystore import KeystoreManager


class TestKeystoreManager(unittest.TestCase):
    """Test cases for KeystoreManager."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.keystore_path = os.path.join(self.test_dir, 'test_keystore')
        self.km = KeystoreManager(self.keystore_path)
        
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
        
    def test_keystore_initialization(self):
        """Test keystore initialization."""
        self.assertTrue(Path(self.keystore_path).exists())
        
    def test_generate_rsa_keypair(self):
        """Test RSA key pair generation."""
        key_name = "test_key"
        private_key_path, public_key_path = self.km.generate_rsa_keypair(
            key_size=2048, 
            key_name=key_name
        )
        
        self.assertTrue(Path(private_key_path).exists())
        self.assertTrue(Path(public_key_path).exists())
        
        # Check file permissions
        private_stat = Path(private_key_path).stat()
        self.assertEqual(oct(private_stat.st_mode)[-3:], '600')
        
    def test_list_keys(self):
        """Test listing keys in keystore."""
        # Generate a test key
        key_name = "test_list_key"
        self.km.generate_rsa_keypair(key_name=key_name)
        
        keys = self.km.list_keys()
        self.assertIn(key_name, keys)
        self.assertIn('private_key', keys[key_name])
        self.assertIn('public_key', keys[key_name])
        
    def test_encrypt_decrypt_small_data(self):
        """Test encryption and decryption of small data."""
        key_name = "encrypt_test_key"
        private_key_path, public_key_path = self.km.generate_rsa_keypair(key_name=key_name)
        
        test_data = b"Hello, World!"
        
        # Encrypt data
        encrypted_data = self.km.encrypt_data(test_data, public_key_path)
        self.assertNotEqual(test_data, encrypted_data)
        
        # Decrypt data
        decrypted_data = self.km.decrypt_data(encrypted_data, private_key_path, key_name)
        self.assertEqual(test_data, decrypted_data)
        
    def test_encrypt_decrypt_large_data(self):
        """Test encryption and decryption of large data (hybrid encryption)."""
        key_name = "large_encrypt_test_key"
        private_key_path, public_key_path = self.km.generate_rsa_keypair(key_name=key_name)
        
        # Large test data that triggers hybrid encryption
        test_data = b"A" * 1000
        
        # Encrypt data
        encrypted_data = self.km.encrypt_data(test_data, public_key_path)
        self.assertNotEqual(test_data, encrypted_data)
        self.assertGreater(len(encrypted_data), 256)  # Should be larger due to hybrid encryption
        
        # Decrypt data
        decrypted_data = self.km.decrypt_data(encrypted_data, private_key_path, key_name)
        self.assertEqual(test_data, decrypted_data)
        
    def test_delete_key(self):
        """Test key deletion."""
        key_name = "delete_test_key"
        self.km.generate_rsa_keypair(key_name=key_name)
        
        # Verify key exists
        keys_before = self.km.list_keys()
        self.assertIn(key_name, keys_before)
        
        # Delete key
        success = self.km.delete_key(key_name)
        self.assertTrue(success)
        
        # Verify key no longer exists
        keys_after = self.km.list_keys()
        self.assertNotIn(key_name, keys_after)
        
    def test_invalid_key_size(self):
        """Test that invalid key sizes raise appropriate errors."""
        with self.assertRaises(ValueError):
            self.km.generate_rsa_keypair(key_size=1024)  # Too small


if __name__ == '__main__':
    unittest.main()