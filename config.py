"""
Configuration constants for ChartVault application.
Centralized configuration management with security best practices.
"""

import os
from pathlib import Path

# Application metadata
APP_NAME = "ChartVault"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Professional Secure Graph Generator with Enterprise-Grade Security"

# Paths
BASE_DIR = Path(__file__).parent
DATABASE_PATH = BASE_DIR / "data" / "chartvault.db"
DATA_DIR = BASE_DIR / "data"

# Security configurations
SESSION_TIMEOUT = 1800  # 30 minutes in seconds
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes in seconds
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_NUMBERS = True
PASSWORD_REQUIRE_SPECIAL = True

# MFA Configuration
MFA_ISSUER = "ChartVault"
MFA_WINDOW = 1  # Number of windows to check for TOTP

# Encryption
ENCRYPTION_ALGORITHM = "AES-256-GCM"
ENCRYPTION_KEY_FILE = BASE_DIR / ".encryption_key"

# Database
DB_TIMEOUT = 30
DB_CONNECTION_RETRIES = 3

# Input validation constraints
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
USERNAME_PATTERN = r"^[a-zA-Z0-9_-]+$"
GRAPH_NAME_MAX_LENGTH = 100
CHART_TITLE_MAX_LENGTH = 255
AXIS_LABEL_MAX_LENGTH = 100
DESCRIPTION_MAX_LENGTH = 1000

# Graph data constraints
MAX_CHART_POINTS = 10000
MAX_PIE_SLICES = 50
MIN_CHART_POINTS = 2
HISTOGRAM_MAX_BINS = 100
HISTOGRAM_MIN_BINS = 2

# Proportion validation
PROPORTION_TOLERANCE = 0.01  # Allow 1% tolerance for rounding errors

# File upload constraints
MAX_FILE_SIZE_MB = 50

# OWASP Top 10 Mitigation
# A01: Broken Access Control - Session timeout, role-based access
# A02: Cryptographic Failures - AES-256 encryption, secure key storage
# A03: Injection - Input validation, parameterized queries, sanitization
# A04: Insecure Design - MFA, secure defaults, audit logging
# A05: Security Misconfiguration - Secure session storage, secure headers
# A06: Vulnerable Components - Regular dependency updates (specified in requirements.txt)
# A07: Authentication Failures - MFA, password policy, account lockout
# A08: Data Integrity Failures - Input validation, signed sessions
# A09: Logging Failures - Comprehensive audit logging
# A10: SSRF - No external API calls, input validation

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = BASE_DIR / "logs" / "chartvault.log"
AUDIT_LOG_FILE = BASE_DIR / "logs" / "audit.log"

# Custom color scheme (modern professional palette)
COLORS = {
    "primary": "#1E3A8A",      # Deep blue
    "secondary": "#3B82F6",    # Bright blue
    "success": "#10B981",      # Green
    "warning": "#F59E0B",      # Amber
    "danger": "#EF4444",       # Red
    "info": "#0EA5E9",         # Sky blue
    "light_bg": "#F8FAFC",     # Light gray-blue
    "dark_bg": "#0F172A",      # Dark navy
    "border": "#E2E8F0",       # Light border
    "text_primary": "#1E293B", # Dark text
    "text_secondary": "#64748B" # Medium gray text
}

# UI Settings
SIDEBAR_WIDTH = 350
MAIN_CONTENT_MAX_WIDTH = 1400
GRAPH_FIGURE_HEIGHT = 600
GRAPH_FIGURE_WIDTH = 1000

# Default user preferences
DEFAULT_GRAPH_TYPE = "line"
DEFAULT_THEME = "light"

# Defensive measures
ENABLE_RATE_LIMITING = True
ENABLE_CSRF_PROTECTION = True
ENABLE_CONTENT_SECURITY_POLICY = True
ENABLE_INPUT_SANITIZATION = True
ENABLE_AUDIT_LOGGING = True
ENABLE_MFA_ENFORCEMENT = False  # Optional but recommended

# Export all configuration
__all__ = [
    'APP_NAME', 'APP_VERSION', 'APP_DESCRIPTION', 'BASE_DIR', 'DATABASE_PATH',
    'SESSION_TIMEOUT', 'MAX_LOGIN_ATTEMPTS', 'LOCKOUT_DURATION',
    'PASSWORD_MIN_LENGTH', 'PASSWORD_MAX_LENGTH', 'PASSWORD_REQUIRE_UPPERCASE',
    'PASSWORD_REQUIRE_LOWERCASE', 'PASSWORD_REQUIRE_NUMBERS', 'PASSWORD_REQUIRE_SPECIAL',
    'MFA_ISSUER', 'MFA_WINDOW', 'ENCRYPTION_ALGORITHM', 'ENCRYPTION_KEY_FILE',
    'USERNAME_MIN_LENGTH', 'USERNAME_MAX_LENGTH', 'USERNAME_PATTERN',
    'GRAPH_NAME_MAX_LENGTH', 'CHART_TITLE_MAX_LENGTH', 'AXIS_LABEL_MAX_LENGTH',
    'MAX_CHART_POINTS', 'MAX_PIE_SLICES', 'MIN_CHART_POINTS', 'HISTOGRAM_MAX_BINS',
    'HISTOGRAM_MIN_BINS', 'PROPORTION_TOLERANCE', 'COLORS'
]
