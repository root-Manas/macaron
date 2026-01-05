"""
Custom exceptions for Security Recon Platform
"""


class ReconException(Exception):
    """Base exception for all recon errors"""
    pass


class ToolNotFoundError(ReconException):
    """Raised when a required tool is not installed"""
    pass


class ToolExecutionError(ReconException):
    """Raised when a tool fails to execute properly"""
    pass


class ConfigurationError(ReconException):
    """Raised when configuration is invalid or missing"""
    pass


class ValidationError(ReconException):
    """Raised when input validation fails"""
    pass


class ScanError(ReconException):
    """Raised when a scan operation fails"""
    pass


class DatabaseError(ReconException):
    """Raised when database operations fail"""
    pass
