import os
import json
import hashlib
import secrets
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import re


class SecurityOperations:
    """Implements security operations and best practices."""
    
    def __init__(self, audit_log_path: str = "security_audit.log"):
        self.audit_log_path = Path(audit_log_path)
        self._setup_logging()
        self.password_policy = {
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special": True,
            "forbidden_patterns": ["password", "123456", "qwerty", "admin"]
        }
        
    def _setup_logging(self):
        """Set up security audit logging."""
        # Security audit logger
        self.audit_logger = logging.getLogger("security_audit")
        audit_handler = logging.FileHandler(self.audit_log_path, mode='a')
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
        )
        audit_handler.setFormatter(audit_formatter)
        self.audit_logger.addHandler(audit_handler)
        self.audit_logger.setLevel(logging.INFO)
        
        # Regular logger
        self.logger = logging.getLogger(__name__)
    
    def audit_log(self, action: str, user: str = "system", details: Dict[str, Any] = None):
        """Log security-relevant actions for audit purposes."""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "user": user,
            "details": details or {}
        }
        self.audit_logger.info(json.dumps(audit_entry))
    
    def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate a cryptographically secure password.
        
        Args:
            length: Password length (minimum 12)
            
        Returns:
            Secure password string
        """
        if length < 12:
            raise ValueError("Password length must be at least 12 characters")
        
        # Character sets
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each required set
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill remaining length with random characters from all sets
        all_chars = uppercase + lowercase + digits + special
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        result = ''.join(password)
        self.audit_log("password_generated", details={"length": length})
        
        return result
    
    def validate_password(self, password: str) -> Dict[str, Any]:
        """
        Validate password against security policy.
        
        Args:
            password: Password to validate
            
        Returns:
            Validation result with score and recommendations
        """
        result = {
            "valid": True,
            "score": 0,
            "max_score": 100,
            "issues": [],
            "recommendations": []
        }
        
        # Length check
        if len(password) < self.password_policy["min_length"]:
            result["issues"].append(f"Password too short (minimum {self.password_policy['min_length']} characters)")
            result["valid"] = False
        else:
            result["score"] += 20
        
        # Character requirements
        if self.password_policy["require_uppercase"] and not re.search(r'[A-Z]', password):
            result["issues"].append("Password must contain uppercase letters")
            result["valid"] = False
        else:
            result["score"] += 15
            
        if self.password_policy["require_lowercase"] and not re.search(r'[a-z]', password):
            result["issues"].append("Password must contain lowercase letters")
            result["valid"] = False
        else:
            result["score"] += 15
            
        if self.password_policy["require_digits"] and not re.search(r'\d', password):
            result["issues"].append("Password must contain digits")
            result["valid"] = False
        else:
            result["score"] += 15
            
        if self.password_policy["require_special"] and not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            result["issues"].append("Password must contain special characters")
            result["valid"] = False
        else:
            result["score"] += 15
        
        # Forbidden patterns
        password_lower = password.lower()
        for pattern in self.password_policy["forbidden_patterns"]:
            if pattern in password_lower:
                result["issues"].append(f"Password contains forbidden pattern: {pattern}")
                result["valid"] = False
                result["score"] -= 10
        
        # Complexity bonus
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.8:
            result["score"] += 10  # High character diversity
        
        # Length bonus
        if len(password) >= 20:
            result["score"] += 10
        
        # Cap score at maximum
        result["score"] = min(result["score"], result["max_score"])
        
        # Recommendations
        if result["score"] < 60:
            result["recommendations"].append("Consider using a longer password")
            result["recommendations"].append("Avoid common words and patterns")
        if result["score"] < 80:
            result["recommendations"].append("Add more character variety")
        
        self.audit_log("password_validated", details={
            "valid": result["valid"],
            "score": result["score"],
            "issues_count": len(result["issues"])
        })
        
        return result
    
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Dict[str, str]:
        """
        Hash a password using PBKDF2 with SHA-256.
        
        Args:
            password: Password to hash
            salt: Optional salt (will generate if not provided)
            
        Returns:
            Dictionary with hash, salt, and metadata
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Use PBKDF2 with 100,000 iterations
        iterations = 100000
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        
        result = {
            "hash": password_hash.hex(),
            "salt": salt.hex(),
            "algorithm": "pbkdf2_hmac",
            "hash_function": "sha256",
            "iterations": iterations,
            "created": datetime.utcnow().isoformat()
        }
        
        self.audit_log("password_hashed", details={
            "algorithm": result["algorithm"],
            "iterations": iterations
        })
        
        return result
    
    def verify_password(self, password: str, stored_hash: str, salt: str, iterations: int = 100000) -> bool:
        """
        Verify a password against a stored hash.
        
        Args:
            password: Password to verify
            stored_hash: Stored password hash (hex)
            salt: Salt used for hashing (hex)
            iterations: Number of PBKDF2 iterations
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            salt_bytes = bytes.fromhex(salt)
            computed_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt_bytes,
                iterations
            )
            
            result = secrets.compare_digest(computed_hash.hex(), stored_hash)
            
            self.audit_log("password_verified", details={
                "success": result,
                "iterations": iterations
            })
            
            return result
            
        except Exception as e:
            self.audit_log("password_verification_error", details={
                "error": str(e)
            })
            return False
    
    def scan_for_secrets(self, directory_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan files for potential secrets and sensitive information.
        
        Args:
            directory_path: Directory to scan
            
        Returns:
            Dictionary of findings by file
        """
        findings = {}
        
        # Common secret patterns
        patterns = {
            "api_key": r'(?i)api[_-]?key[s]?["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})',
            "password": r'(?i)password["\s]*[:=]["\s]*["\']([^"\']{8,})["\']',
            "private_key": r'-----BEGIN[A-Z\s]+PRIVATE KEY-----',
            "aws_access_key": r'AKIA[0-9A-Z]{16}',
            "jwt_token": r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            "ssh_private_key": r'-----BEGIN OPENSSH PRIVATE KEY-----',
            "database_url": r'(?i)(mongodb|mysql|postgresql)://[^\s"\']*',
            "secret_key": r'(?i)secret[_-]?key[s]?["\s]*[:=]["\s]*([a-zA-Z0-9]{16,})'
        }
        
        scan_extensions = {'.py', '.js', '.json', '.yaml', '.yml', '.env', '.config', '.ini'}
        
        directory = Path(directory_path)
        for file_path in directory.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in scan_extensions:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    file_findings = []
                    for pattern_name, pattern in patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            file_findings.append({
                                "type": pattern_name,
                                "line": line_num,
                                "match": match.group(0)[:100] + "..." if len(match.group(0)) > 100 else match.group(0)
                            })
                    
                    if file_findings:
                        findings[str(file_path)] = file_findings
                        
                except Exception as e:
                    self.logger.warning(f"Could not scan file {file_path}: {e}")
        
        self.audit_log("secrets_scan_completed", details={
            "directory": directory_path,
            "files_with_findings": len(findings),
            "total_findings": sum(len(f) for f in findings.values())
        })
        
        return findings
    
    def check_file_permissions(self, directory_path: str) -> Dict[str, Any]:
        """
        Check file permissions for security issues.
        
        Args:
            directory_path: Directory to check
            
        Returns:
            Dictionary with permission analysis
        """
        issues = []
        checked_files = 0
        
        directory = Path(directory_path)
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                checked_files += 1
                stat_info = file_path.stat()
                mode = stat_info.st_mode
                
                # Check for world-writable files
                if mode & 0o002:
                    issues.append({
                        "file": str(file_path),
                        "issue": "world_writable",
                        "permissions": oct(mode)[-3:],
                        "severity": "high"
                    })
                
                # Check for world-readable sensitive files
                if file_path.suffix in {'.key', '.pem', '.p12', '.pfx'} and mode & 0o004:
                    issues.append({
                        "file": str(file_path),
                        "issue": "sensitive_file_world_readable",
                        "permissions": oct(mode)[-3:],
                        "severity": "high"
                    })
                
                # Check for executable files in unusual locations
                if mode & 0o111 and file_path.suffix in {'.txt', '.log', '.json', '.yaml', '.yml'}:
                    issues.append({
                        "file": str(file_path),
                        "issue": "unnecessary_execute_permission",
                        "permissions": oct(mode)[-3:],
                        "severity": "medium"
                    })
        
        result = {
            "checked_files": checked_files,
            "issues": issues,
            "high_severity": len([i for i in issues if i["severity"] == "high"]),
            "medium_severity": len([i for i in issues if i["severity"] == "medium"]),
            "low_severity": len([i for i in issues if i["severity"] == "low"])
        }
        
        self.audit_log("permission_check_completed", details={
            "directory": directory_path,
            "checked_files": checked_files,
            "total_issues": len(issues)
        })
        
        return result
    
    def generate_security_report(self, directory_path: str) -> Dict[str, Any]:
        """
        Generate a comprehensive security report for a directory.
        
        Args:
            directory_path: Directory to analyze
            
        Returns:
            Comprehensive security report
        """
        report_start = datetime.utcnow()
        
        report = {
            "timestamp": report_start.isoformat(),
            "directory": directory_path,
            "summary": {},
            "findings": {}
        }
        
        try:
            # Scan for secrets
            self.logger.info("Scanning for secrets...")
            secrets_findings = self.scan_for_secrets(directory_path)
            report["findings"]["secrets"] = secrets_findings
            
            # Check file permissions
            self.logger.info("Checking file permissions...")
            permission_findings = self.check_file_permissions(directory_path)
            report["findings"]["permissions"] = permission_findings
            
            # Generate summary
            total_secret_findings = sum(len(f) for f in secrets_findings.values())
            total_permission_issues = len(permission_findings["issues"])
            
            report["summary"] = {
                "total_files_scanned": permission_findings["checked_files"],
                "secret_findings": total_secret_findings,
                "permission_issues": total_permission_issues,
                "high_severity_issues": permission_findings["high_severity"],
                "scan_duration_seconds": (datetime.utcnow() - report_start).total_seconds(),
                "overall_risk": self._calculate_risk_level(total_secret_findings, total_permission_issues)
            }
            
            # Save report
            report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            report_path = Path(directory_path) / report_filename
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.audit_log("security_report_generated", details={
                "report_file": str(report_path),
                "total_findings": total_secret_findings + total_permission_issues
            })
            
            self.logger.info(f"Security report saved to: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate security report: {e}")
            report["error"] = str(e)
        
        return report
    
    def _calculate_risk_level(self, secret_findings: int, permission_issues: int) -> str:
        """Calculate overall risk level based on findings."""
        total_issues = secret_findings + permission_issues
        
        if total_issues == 0:
            return "low"
        elif total_issues <= 5:
            return "medium"
        else:
            return "high"
    
    def create_security_policy(self) -> Dict[str, Any]:
        """Create a security policy configuration."""
        policy = {
            "password_policy": self.password_policy,
            "file_permissions": {
                "private_keys": "600",
                "certificates": "644",
                "config_files": "640",
                "executable_files": "755",
                "directories": "755"
            },
            "encryption_standards": {
                "minimum_key_size": 2048,
                "allowed_algorithms": ["AES-256", "RSA-2048", "RSA-4096", "ECDSA-P256"],
                "hash_functions": ["SHA-256", "SHA-384", "SHA-512"],
                "password_hashing": "PBKDF2-SHA256"
            },
            "audit_requirements": {
                "log_all_key_operations": True,
                "log_certificate_operations": True,
                "log_authentication_attempts": True,
                "retain_logs_days": 90
            },
            "certificate_policies": {
                "minimum_validity_days": 1,
                "maximum_validity_days": 365,
                "require_san": False,
                "allowed_key_usages": ["digital_signature", "key_encipherment"]
            }
        }
        
        policy_file = "security_policy.json"
        with open(policy_file, 'w') as f:
            json.dump(policy, f, indent=2)
        
        self.audit_log("security_policy_created", details={
            "policy_file": policy_file
        })
        
        return policy