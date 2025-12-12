"""
Comprehensive Input Validation Utilities for Security
======================================================
This module provides validation and sanitization for all user inputs
to prevent OWASP Top 10 vulnerabilities including:
- A03:2021 - Injection (SQL, Command, LDAP, XPath)
- A07:2021 - Cross-Site Scripting (XSS)
- A10:2021 - Server-Side Request Forgery (SSRF)
"""
from pydantic import validator
import re
from typing import Optional, List, Tuple
import ipaddress
import html
from urllib.parse import urlparse, parse_qs
import logging

logger = logging.getLogger(__name__)


class SecurityValidators:
    """
    Centralized security validators for input sanitization and validation.
    """
    
    # Dangerous patterns for injection detection
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)",
        r"(\b(OR|AND)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?)",
        r"(--\s*$|#\s*$|/\*.*\*/)",
        r"(\bEXEC\s*\(|\bEXECUTE\s*\()",
        r"(;\s*(DROP|DELETE|UPDATE|INSERT)\s)",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"vbscript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$]",
        r"\$\([^)]+\)",
        r"`[^`]+`",
        r"\|\|",
        r"&&",
    ]
    
    # Private IP ranges for SSRF prevention
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
        ipaddress.ip_network('fe80::/10'),
    ]
    
    BLOCKED_HOSTNAMES = {
        'localhost',
        'localhost.localdomain',
        '127.0.0.1',
        '0.0.0.0',
        '::1',
        'metadata.google.internal',
        '169.254.169.254',
        'metadata.azure.com',
    }
    
    @staticmethod
    def validate_domain(domain: str) -> str:
        """
        Validate domain name format with comprehensive security checks.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            Validated and normalized domain name
            
        Raises:
            ValueError: If domain is invalid or potentially malicious
        """
        if not domain or len(domain) < 3:
            raise ValueError("Domain must be at least 3 characters long")
        
        if len(domain) > 253:
            raise ValueError("Domain name too long (max 253 characters)")
        
        # Normalize to lowercase
        domain = domain.lower().strip()
        
        # Basic domain regex
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            raise ValueError("Invalid domain format")
        
        # Prevent common injection patterns
        dangerous_patterns = ['..', '//', '\\', '<', '>', '|', '&', ';', '%00', '\x00']
        if any(pattern in domain for pattern in dangerous_patterns):
            raise ValueError("Domain contains invalid characters")
        
        # Check for punycode/IDN homograph attacks
        if 'xn--' in domain:
            # Allow punycode but log for monitoring
            logger.info(f"Punycode domain detected: {domain}")
        
        return domain

    @staticmethod
    def validate_url(url: str, allow_internal: bool = False) -> str:
        """
        Validate URL format with SSRF and injection prevention.
        
        Args:
            url: URL to validate
            allow_internal: Whether to allow internal network URLs (default: False)
            
        Returns:
            Validated URL
            
        Raises:
            ValueError: If URL is invalid or potentially malicious
        """
        if not url or len(url) < 10:
            raise ValueError("URL must be at least 10 characters long")
        
        if len(url) > 2048:
            raise ValueError("URL too long (max 2048 characters)")
        
        url = url.strip()
        
        # Must start with http:// or https://
        if not url.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        
        # Prevent common injection patterns
        dangerous_patterns = ['javascript:', 'data:', 'vbscript:', '<', '>', '\x00', '%00']
        url_lower = url.lower()
        if any(pattern in url_lower for pattern in dangerous_patterns):
            raise ValueError("URL contains potentially dangerous content")
        
        # Parse URL for additional validation
        try:
            parsed = urlparse(url)
        except Exception:
            raise ValueError("Invalid URL format")
        
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("URL must have a valid hostname")
        
        # Check for blocked hostnames (SSRF prevention)
        if not allow_internal:
            if hostname.lower() in SecurityValidators.BLOCKED_HOSTNAMES:
                raise ValueError(f"Access to {hostname} is not allowed")
            
            # Check if hostname is an IP address in private range
            try:
                ip = ipaddress.ip_address(hostname)
                for private_range in SecurityValidators.PRIVATE_IP_RANGES:
                    if ip in private_range:
                        raise ValueError("Access to internal IP addresses is not allowed")
            except ValueError:
                # Not an IP address, hostname will be resolved
                pass
        
        # Check for suspicious port numbers
        blocked_ports = {22, 23, 25, 445, 3389, 5432, 3306, 27017, 6379, 11211}
        if parsed.port and parsed.port in blocked_ports:
            raise ValueError(f"Access to port {parsed.port} is not allowed")
        
        return url

    @staticmethod
    def validate_ip(ip: str) -> str:
        """
        Validate IP address format.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            Validated IP address
            
        Raises:
            ValueError: If IP address is invalid
        """
        if not ip:
            raise ValueError("IP address cannot be empty")
        
        ip = ip.strip()
        
        try:
            validated_ip = ipaddress.ip_address(ip)
            return str(validated_ip)
        except ValueError:
            raise ValueError("Invalid IP address format")

    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000, 
                        allow_html: bool = False,
                        allow_newlines: bool = True) -> str:
        """
        Sanitize string input to prevent XSS and injection attacks.
        
        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            allow_html: Whether to allow HTML (default: False - will be escaped)
            allow_newlines: Whether to preserve newlines
            
        Returns:
            Sanitized string
        """
        if not value:
            return ""
        
        if not isinstance(value, str):
            value = str(value)
        
        # Truncate to max length
        value = value[:max_length]
        
        # Remove null bytes and control characters
        value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
        
        # Escape HTML if not allowed
        if not allow_html:
            value = html.escape(value)
        
        # Handle newlines
        if not allow_newlines:
            value = value.replace('\n', ' ').replace('\r', ' ')
        
        return value.strip()

    @staticmethod
    def sanitize_package_name(name: str) -> str:
        """
        Sanitize package name for dependency scanning.
        
        Args:
            name: Package name to sanitize
            
        Returns:
            Sanitized package name
            
        Raises:
            ValueError: If package name is invalid
        """
        if not name or len(name) < 1:
            raise ValueError("Package name cannot be empty")
        
        if len(name) > 214:  # npm package name limit
            raise ValueError("Package name too long")
        
        name = name.strip().lower()
        
        # Allow only alphanumeric, hyphens, underscores, dots, and @/
        if not re.match(r'^(@[a-zA-Z0-9._-]+\/)?[a-zA-Z0-9._-]+$', name):
            raise ValueError("Package name contains invalid characters")
        
        return name

    @staticmethod
    def validate_email(email: str) -> str:
        """
        Validate email address format.
        
        Args:
            email: Email address to validate
            
        Returns:
            Validated email address (lowercase)
            
        Raises:
            ValueError: If email is invalid
        """
        if not email:
            raise ValueError("Email cannot be empty")
        
        email = email.strip().lower()
        
        if len(email) > 254:
            raise ValueError("Email address too long")
        
        # RFC 5322 compliant email pattern (simplified)
        email_pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email format")
        
        return email

    @staticmethod
    def validate_password(password: str) -> Tuple[bool, List[str]]:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if not password:
            return False, ["Password is required"]
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters")
        
        if len(password) > 128:
            errors.append("Password must be at most 128 characters")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            errors.append("Password must contain at least one special character")
        
        # Check for common patterns
        common_patterns = [
            r'^password',
            r'^123456',
            r'^qwerty',
            r'^letmein',
            r'^admin',
            r'(.)\1{3,}'  # 4+ repeated characters
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                errors.append("Password contains a common pattern")
                break
        
        return len(errors) == 0, errors

    @staticmethod
    def validate_uuid(uuid_str: str) -> str:
        """
        Validate UUID format.
        
        Args:
            uuid_str: UUID string to validate
            
        Returns:
            Validated UUID string (lowercase)
            
        Raises:
            ValueError: If UUID is invalid
        """
        if not uuid_str:
            raise ValueError("UUID cannot be empty")
        
        uuid_str = uuid_str.strip().lower()
        
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        
        if not re.match(uuid_pattern, uuid_str):
            raise ValueError("Invalid UUID format")
        
        return uuid_str

    @staticmethod
    def detect_injection(value: str) -> Tuple[bool, str]:
        """
        Detect potential injection attacks in input.
        
        Args:
            value: Input value to check
            
        Returns:
            Tuple of (is_suspicious, attack_type)
        """
        if not value:
            return False, ""
        
        # Check for SQL injection
        for pattern in SecurityValidators.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True, "SQL Injection"
        
        # Check for XSS
        for pattern in SecurityValidators.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True, "Cross-Site Scripting"
        
        # Check for command injection
        for pattern in SecurityValidators.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value):
                return True, "Command Injection"
        
        return False, ""

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename to prevent path traversal attacks.
        
        Args:
            filename: Filename to sanitize
            
        Returns:
            Sanitized filename
            
        Raises:
            ValueError: If filename is invalid
        """
        if not filename:
            raise ValueError("Filename cannot be empty")
        
        # Remove path separators
        filename = filename.replace('/', '').replace('\\', '')
        
        # Remove null bytes
        filename = filename.replace('\x00', '')
        
        # Remove path traversal attempts
        filename = re.sub(r'\.\.+', '.', filename)
        
        # Remove special characters
        filename = re.sub(r'[<>:"|?*]', '', filename)
        
        # Limit length
        filename = filename[:255]
        
        if not filename or filename in ['.', '..']:
            raise ValueError("Invalid filename")
        
        return filename

    @staticmethod
    def validate_json_depth(data: dict, max_depth: int = 10, current_depth: int = 0) -> bool:
        """
        Validate JSON nesting depth to prevent DoS attacks.
        
        Args:
            data: JSON data to validate
            max_depth: Maximum allowed nesting depth
            current_depth: Current depth (used in recursion)
            
        Returns:
            True if depth is within limits
            
        Raises:
            ValueError: If depth exceeds limit
        """
        if current_depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum of {max_depth}")
        
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, (dict, list)):
                    SecurityValidators.validate_json_depth(value, max_depth, current_depth + 1)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    SecurityValidators.validate_json_depth(item, max_depth, current_depth + 1)
        
        return True
