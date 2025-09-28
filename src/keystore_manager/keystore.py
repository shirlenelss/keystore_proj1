import os
import secrets
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
from datetime import datetime


class KeystoreManager:
    """Manages cryptographic keys with secure storage and operations."""
    
    def __init__(self, keystore_path: str = "keystore"):
        self.keystore_path = Path(keystore_path)
        self.keystore_path.mkdir(exist_ok=True, mode=0o700)  # Secure directory permissions
        self._setup_logging()
        
    def _setup_logging(self):
        """Set up secure logging for keystore operations."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('keystore_operations.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def generate_rsa_keypair(self, key_size: int = 2048, key_name: str = "default") -> Tuple[str, str]:
        """
        Generate an RSA key pair with specified key size.
        
        Args:
            key_size: Size of the RSA key (default: 2048)
            key_name: Name identifier for the key pair
            
        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        if key_size < 2048:
            raise ValueError("Key size must be at least 2048 bits for security")
            
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key with password protection
            password = self._generate_secure_password()
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save keys to files
            private_key_path = self.keystore_path / f"{key_name}_private.pem"
            public_key_path = self.keystore_path / f"{key_name}_public.pem"
            
            # Write private key with secure permissions
            private_key_path.write_bytes(private_pem)
            private_key_path.chmod(0o600)
            
            # Write public key
            public_key_path.write_bytes(public_pem)
            public_key_path.chmod(0o644)
            
            # Store password securely (in production, use a proper secret manager)
            password_file = self.keystore_path / f"{key_name}_password.txt"
            password_file.write_bytes(password)
            password_file.chmod(0o600)
            
            # Log the operation (without sensitive data)
            self.logger.info(f"Generated RSA key pair: {key_name} ({key_size} bits)")
            
            return str(private_key_path), str(public_key_path)
            
        except Exception as e:
            self.logger.error(f"Failed to generate RSA key pair: {e}")
            raise
    
    def _generate_secure_password(self, length: int = 32) -> bytes:
        """Generate a cryptographically secure password."""
        return secrets.token_bytes(length)
    
    def load_private_key(self, key_path: str, key_name: str = "default") -> Any:
        """
        Load a private key from file.
        
        Args:
            key_path: Path to the private key file
            key_name: Name identifier for the key
            
        Returns:
            Loaded private key object
        """
        try:
            password_file = self.keystore_path / f"{key_name}_password.txt"
            if password_file.exists():
                password = password_file.read_bytes()
            else:
                password = None
            
            with open(key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password,
                    backend=default_backend()
                )
            
            self.logger.info(f"Loaded private key: {key_path}")
            return private_key
            
        except Exception as e:
            self.logger.error(f"Failed to load private key {key_path}: {e}")
            raise
    
    def load_public_key(self, key_path: str) -> Any:
        """
        Load a public key from file.
        
        Args:
            key_path: Path to the public key file
            
        Returns:
            Loaded public key object
        """
        try:
            with open(key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            
            self.logger.info(f"Loaded public key: {key_path}")
            return public_key
            
        except Exception as e:
            self.logger.error(f"Failed to load public key {key_path}: {e}")
            raise
    
    def encrypt_data(self, data: bytes, public_key_path: str) -> bytes:
        """
        Encrypt data using RSA public key.
        
        Args:
            data: Data to encrypt
            public_key_path: Path to public key file
            
        Returns:
            Encrypted data
        """
        try:
            public_key = self.load_public_key(public_key_path)
            
            # RSA can only encrypt small amounts of data, so for larger data,
            # we'd typically use hybrid encryption (AES + RSA)
            if len(data) > 190:  # Conservative limit for RSA-2048
                return self._hybrid_encrypt(data, public_key)
            
            encrypted_data = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.logger.info("Data encrypted successfully")
            return encrypted_data
            
        except Exception as e:
            self.logger.error(f"Failed to encrypt data: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: bytes, private_key_path: str, key_name: str = "default") -> bytes:
        """
        Decrypt data using RSA private key.
        
        Args:
            encrypted_data: Encrypted data to decrypt
            private_key_path: Path to private key file
            key_name: Name identifier for the key
            
        Returns:
            Decrypted data
        """
        try:
            private_key = self.load_private_key(private_key_path, key_name)
            
            # Check if this is hybrid encrypted data based on key size
            key_size_bytes = private_key.key_size // 8
            if len(encrypted_data) > key_size_bytes:  # Likely hybrid encryption
                return self._hybrid_decrypt(encrypted_data, private_key)
            
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.logger.info("Data decrypted successfully")
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"Failed to decrypt data: {e}")
            raise
    
    def _hybrid_encrypt(self, data: bytes, public_key) -> bytes:
        """Hybrid encryption: AES for data, RSA for AES key."""
        # Generate AES key
        aes_key = secrets.token_bytes(32)  # 256-bit key
        iv = secrets.token_bytes(16)  # 128-bit IV
        
        # Encrypt data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad data to AES block size
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length]) * pad_length
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine encrypted key, IV, and encrypted data
        return encrypted_key + iv + encrypted_data
    
    def _hybrid_decrypt(self, encrypted_data: bytes, private_key) -> bytes:
        """Hybrid decryption: RSA for AES key, AES for data."""
        # Get the key size in bytes (RSA key size / 8)
        key_size_bytes = private_key.key_size // 8
        
        # Extract components
        encrypted_key = encrypted_data[:key_size_bytes]  # RSA ciphertext size matches key size
        iv = encrypted_data[key_size_bytes:key_size_bytes+16]  # 16-byte IV
        encrypted_content = encrypted_data[key_size_bytes+16:]
        
        # Decrypt AES key with RSA
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # Remove padding
        pad_length = padded_data[-1]
        return padded_data[:-pad_length]
    
    def list_keys(self) -> Dict[str, Any]:
        """List all keys in the keystore."""
        keys = {}
        for key_file in self.keystore_path.glob("*.pem"):
            if "private" in key_file.name:
                key_name = key_file.name.replace("_private.pem", "")
                public_key_file = self.keystore_path / f"{key_name}_public.pem"
                
                keys[key_name] = {
                    "private_key": str(key_file),
                    "public_key": str(public_key_file) if public_key_file.exists() else None,
                    "created": datetime.fromtimestamp(key_file.stat().st_ctime).isoformat()
                }
        
        return keys
    
    def delete_key(self, key_name: str) -> bool:
        """
        Securely delete a key pair.
        
        Args:
            key_name: Name identifier for the key pair to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            files_to_delete = [
                self.keystore_path / f"{key_name}_private.pem",
                self.keystore_path / f"{key_name}_public.pem",
                self.keystore_path / f"{key_name}_password.txt"
            ]
            
            deleted_count = 0
            for file_path in files_to_delete:
                if file_path.exists():
                    # Securely overwrite file before deletion
                    self._secure_delete(file_path)
                    deleted_count += 1
            
            if deleted_count > 0:
                self.logger.info(f"Deleted key pair: {key_name}")
                return True
            else:
                self.logger.warning(f"No key pair found with name: {key_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to delete key pair {key_name}: {e}")
            raise
    
    def _secure_delete(self, file_path: Path):
        """Securely delete a file by overwriting it multiple times."""
        if file_path.exists():
            file_size = file_path.stat().st_size
            
            # Overwrite with random data multiple times
            with open(file_path, 'r+b') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally delete the file
            file_path.unlink()