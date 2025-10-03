"""Input validation utilities for security"""
from pydantic import validator
import re
from typing import Optional
import ipaddress

class SecurityValidators:
    @staticmethod
    def validate_domain(domain: str) -> str:
        """Validate domain name format"""
        if not domain or len(domain) < 3:
            raise ValueError("Domain must be at least 3 characters long")
        
        # Basic domain regex
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            raise ValueError("Invalid domain format")
        
        # Prevent common injection patterns
        dangerous_patterns = ['..', '//', '\\', '<', '>', '|', '&', ';']
        if any(pattern in domain for pattern in dangerous_patterns):
            raise ValueError("Domain contains invalid characters")
        
        return domain.lower()

    @staticmethod
    def validate_url(url: str) -> str:
        """Validate URL format"""
        if not url or len(url) < 10:
            raise ValueError("URL must be at least 10 characters long")
        
        # Must start with http:// or https://
        if not url.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        
        # Prevent common injection patterns
        dangerous_patterns = ['javascript:', 'data:', 'vbscript:', '<', '>']
        if any(pattern in url.lower() for pattern in dangerous_patterns):
            raise ValueError("URL contains potentially dangerous content")
        
        return url

    @staticmethod
    def validate_ip(ip: str) -> str:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValueError("Invalid IP address format")

    @staticmethod
    def sanitize_package_name(name: str) -> str:
        """Sanitize package name"""
        if not name or len(name) < 1:
            raise ValueError("Package name cannot be empty")
        
        # Allow only alphanumeric, hyphens, underscores, and dots
        if not re.match(r'^[a-zA-Z0-9._-]+$', name):
            raise ValueError("Package name contains invalid characters")
        
        return name
