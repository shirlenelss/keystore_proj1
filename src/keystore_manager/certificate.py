import os
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import ipaddress


class CertificateManager:
    """Manages X.509 certificates for practice and learning."""
    
    def __init__(self, cert_path: str = "certificates"):
        self.cert_path = Path(cert_path)
        self.cert_path.mkdir(exist_ok=True, mode=0o755)
        self._setup_logging()
        
    def _setup_logging(self):
        """Set up logging for certificate operations."""
        self.logger = logging.getLogger(__name__)
        
    def create_self_signed_certificate(
        self,
        key_size: int = 2048,
        common_name: str = "localhost",
        organization: str = "Keystore Practice",
        country: str = "US",
        validity_days: int = 365,
        alt_names: Optional[List[str]] = None
    ) -> tuple[str, str]:
        """
        Create a self-signed certificate.
        
        Args:
            key_size: RSA key size
            common_name: Certificate common name
            organization: Organization name
            country: Country code
            validity_days: Certificate validity period in days
            alt_names: Subject Alternative Names
            
        Returns:
            Tuple of (certificate_path, private_key_path)
        """
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Create certificate subject
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            
            # Create certificate builder
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(issuer)
            cert_builder = cert_builder.public_key(private_key.public_key())
            cert_builder = cert_builder.serial_number(x509.random_serial_number())
            cert_builder = cert_builder.not_valid_before(datetime.utcnow())
            cert_builder = cert_builder.not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            )
            
            # Add basic constraints
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            
            # Add key usage
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            
            # Add subject alternative names if provided
            if alt_names:
                san_list = []
                for name in alt_names:
                    try:
                        # Try to parse as IP address
                        ip = ipaddress.ip_address(name)
                        san_list.append(x509.IPAddress(ip))
                    except ValueError:
                        # Treat as DNS name
                        san_list.append(x509.DNSName(name))
                
                if san_list:
                    cert_builder = cert_builder.add_extension(
                        x509.SubjectAlternativeName(san_list),
                        critical=False,
                    )
            
            # Sign certificate
            certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())
            
            # Save certificate
            cert_filename = f"{common_name.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.crt"
            key_filename = f"{common_name.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.key"
            
            cert_path = self.cert_path / cert_filename
            key_path = self.cert_path / key_filename
            
            # Write certificate
            with open(cert_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            cert_path.chmod(0o644)
            
            # Write private key
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            key_path.chmod(0o600)
            
            self.logger.info(f"Created self-signed certificate: {cert_filename}")
            
            return str(cert_path), str(key_path)
            
        except Exception as e:
            self.logger.error(f"Failed to create self-signed certificate: {e}")
            raise
    
    def create_ca_certificate(
        self,
        key_size: int = 4096,
        common_name: str = "Practice CA",
        organization: str = "Keystore Practice CA",
        country: str = "US",
        validity_days: int = 3650
    ) -> tuple[str, str]:
        """
        Create a Certificate Authority (CA) certificate.
        
        Args:
            key_size: RSA key size for CA
            common_name: CA common name
            organization: CA organization name
            country: Country code
            validity_days: CA certificate validity period in days
            
        Returns:
            Tuple of (ca_cert_path, ca_key_path)
        """
        try:
            # Generate CA private key
            ca_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Create CA certificate subject
            ca_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
            
            # Create CA certificate builder
            ca_cert_builder = x509.CertificateBuilder()
            ca_cert_builder = ca_cert_builder.subject_name(ca_subject)
            ca_cert_builder = ca_cert_builder.issuer_name(ca_subject)  # Self-signed
            ca_cert_builder = ca_cert_builder.public_key(ca_private_key.public_key())
            ca_cert_builder = ca_cert_builder.serial_number(x509.random_serial_number())
            ca_cert_builder = ca_cert_builder.not_valid_before(datetime.utcnow())
            ca_cert_builder = ca_cert_builder.not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            )
            
            # Add CA basic constraints
            ca_cert_builder = ca_cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            
            # Add CA key usage
            ca_cert_builder = ca_cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            
            # Add subject key identifier
            ca_cert_builder = ca_cert_builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
                critical=False,
            )
            
            # Sign CA certificate
            ca_certificate = ca_cert_builder.sign(ca_private_key, hashes.SHA256(), default_backend())
            
            # Save CA certificate and key
            ca_cert_filename = f"ca_{datetime.now().strftime('%Y%m%d')}.crt"
            ca_key_filename = f"ca_{datetime.now().strftime('%Y%m%d')}.key"
            
            ca_cert_path = self.cert_path / ca_cert_filename
            ca_key_path = self.cert_path / ca_key_filename
            
            # Write CA certificate
            with open(ca_cert_path, "wb") as f:
                f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))
            ca_cert_path.chmod(0o644)
            
            # Write CA private key (encrypted in production!)
            with open(ca_key_path, "wb") as f:
                f.write(ca_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            ca_key_path.chmod(0o600)
            
            self.logger.info(f"Created CA certificate: {ca_cert_filename}")
            
            return str(ca_cert_path), str(ca_key_path)
            
        except Exception as e:
            self.logger.error(f"Failed to create CA certificate: {e}")
            raise
    
    def sign_certificate_request(
        self,
        csr_path: str,
        ca_cert_path: str,
        ca_key_path: str,
        validity_days: int = 365
    ) -> str:
        """
        Sign a certificate signing request (CSR) with a CA certificate.
        
        Args:
            csr_path: Path to the CSR file
            ca_cert_path: Path to the CA certificate
            ca_key_path: Path to the CA private key
            validity_days: Certificate validity period in days
            
        Returns:
            Path to the signed certificate
        """
        try:
            # Load CSR
            with open(csr_path, "rb") as f:
                csr = x509.load_pem_x509_csr(f.read(), default_backend())
            
            # Load CA certificate
            with open(ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            # Load CA private key
            with open(ca_key_path, "rb") as f:
                ca_private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            # Create certificate builder from CSR
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(csr.subject)
            cert_builder = cert_builder.issuer_name(ca_cert.subject)
            cert_builder = cert_builder.public_key(csr.public_key())
            cert_builder = cert_builder.serial_number(x509.random_serial_number())
            cert_builder = cert_builder.not_valid_before(datetime.utcnow())
            cert_builder = cert_builder.not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            )
            
            # Copy extensions from CSR
            for extension in csr.extensions:
                cert_builder = cert_builder.add_extension(
                    extension.value, extension.critical
                )
            
            # Add authority key identifier
            cert_builder = cert_builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False,
            )
            
            # Sign certificate
            certificate = cert_builder.sign(ca_private_key, hashes.SHA256(), default_backend())
            
            # Save signed certificate
            cert_filename = f"signed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.crt"
            cert_path = self.cert_path / cert_filename
            
            with open(cert_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            cert_path.chmod(0o644)
            
            self.logger.info(f"Signed certificate: {cert_filename}")
            
            return str(cert_path)
            
        except Exception as e:
            self.logger.error(f"Failed to sign certificate request: {e}")
            raise
    
    def validate_certificate(self, cert_path: str, ca_cert_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate a certificate and return detailed information.
        
        Args:
            cert_path: Path to the certificate to validate
            ca_cert_path: Optional path to CA certificate for chain validation
            
        Returns:
            Dictionary with validation results and certificate information
        """
        try:
            # Load certificate
            with open(cert_path, "rb") as f:
                certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            result = {
                "valid": True,
                "errors": [],
                "warnings": [],
                "info": {}
            }
            
            # Basic certificate information
            result["info"] = {
                "subject": certificate.subject.rfc4514_string(),
                "issuer": certificate.issuer.rfc4514_string(),
                "serial_number": str(certificate.serial_number),
                "not_valid_before": certificate.not_valid_before.isoformat(),
                "not_valid_after": certificate.not_valid_after.isoformat(),
                "signature_algorithm": certificate.signature_algorithm_oid._name,
                "version": certificate.version.name
            }
            
            # Check if certificate is expired or not yet valid
            now = datetime.utcnow()
            if certificate.not_valid_before > now:
                result["errors"].append("Certificate is not yet valid")
                result["valid"] = False
            elif certificate.not_valid_after < now:
                result["errors"].append("Certificate has expired")
                result["valid"] = False
            elif certificate.not_valid_after < (now + timedelta(days=30)):
                result["warnings"].append("Certificate expires within 30 days")
            
            # Check key size for RSA keys
            public_key = certificate.public_key()
            if hasattr(public_key, 'key_size'):
                key_size = public_key.key_size
                result["info"]["key_size"] = key_size
                if key_size < 2048:
                    result["errors"].append(f"Key size ({key_size}) is below recommended minimum (2048)")
                    result["valid"] = False
            
            # Extract extensions
            extensions = {}
            for extension in certificate.extensions:
                try:
                    extensions[extension.oid._name] = {
                        "critical": extension.critical,
                        "value": str(extension.value)
                    }
                except Exception:
                    extensions[extension.oid._name] = {
                        "critical": extension.critical,
                        "value": "Unable to parse"
                    }
            result["info"]["extensions"] = extensions
            
            # If CA certificate provided, validate chain
            if ca_cert_path:
                try:
                    with open(ca_cert_path, "rb") as f:
                        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                    
                    # Verify signature
                    ca_cert.public_key().verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        certificate.signature_algorithm
                    )
                    result["info"]["ca_validated"] = True
                    
                except Exception as e:
                    result["errors"].append(f"CA validation failed: {str(e)}")
                    result["valid"] = False
            
            self.logger.info(f"Validated certificate: {cert_path}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to validate certificate {cert_path}: {e}")
            return {
                "valid": False,
                "errors": [f"Failed to load certificate: {str(e)}"],
                "warnings": [],
                "info": {}
            }
    
    def list_certificates(self) -> Dict[str, Any]:
        """List all certificates in the certificate directory."""
        certificates = {}
        
        for cert_file in self.cert_path.glob("*.crt"):
            try:
                with open(cert_file, "rb") as f:
                    certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
                
                certificates[cert_file.name] = {
                    "path": str(cert_file),
                    "subject": certificate.subject.rfc4514_string(),
                    "issuer": certificate.issuer.rfc4514_string(),
                    "not_valid_before": certificate.not_valid_before.isoformat(),
                    "not_valid_after": certificate.not_valid_after.isoformat(),
                    "serial_number": str(certificate.serial_number),
                    "is_ca": self._is_ca_certificate(certificate),
                    "created": datetime.fromtimestamp(cert_file.stat().st_ctime).isoformat()
                }
                
            except Exception as e:
                certificates[cert_file.name] = {
                    "path": str(cert_file),
                    "error": f"Failed to parse certificate: {str(e)}"
                }
        
        return certificates
    
    def _is_ca_certificate(self, certificate) -> bool:
        """Check if a certificate is a CA certificate."""
        try:
            basic_constraints = certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            return basic_constraints.ca
        except x509.ExtensionNotFound:
            return False
    
    def create_certificate_chain_pem(self, cert_paths: List[str], output_path: str) -> str:
        """
        Create a certificate chain PEM file from multiple certificates.
        
        Args:
            cert_paths: List of certificate file paths (leaf first, root last)
            output_path: Output path for the chain PEM file
            
        Returns:
            Path to the created chain file
        """
        try:
            chain_content = b""
            
            for cert_path in cert_paths:
                with open(cert_path, "rb") as f:
                    cert_content = f.read()
                    # Ensure certificate ends with newline
                    if not cert_content.endswith(b'\n'):
                        cert_content += b'\n'
                    chain_content += cert_content
            
            chain_path = self.cert_path / output_path
            with open(chain_path, "wb") as f:
                f.write(chain_content)
            chain_path.chmod(0o644)
            
            self.logger.info(f"Created certificate chain: {output_path}")
            
            return str(chain_path)
            
        except Exception as e:
            self.logger.error(f"Failed to create certificate chain: {e}")
            raise