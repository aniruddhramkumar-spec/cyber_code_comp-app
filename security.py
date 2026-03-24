"""
Security module for ChartVault.
Handles authentication, encryption, password validation, and MFA.
"""

import os
import re
import secrets
import hashlib
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from functools import wraps

import bcrypt
import pyotp
from cryptography.fernet import Fernet

from config import (
    PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_REQUIRE_UPPERCASE,
    PASSWORD_REQUIRE_LOWERCASE, PASSWORD_REQUIRE_NUMBERS, PASSWORD_REQUIRE_SPECIAL,
    USERNAME_MIN_LENGTH, USERNAME_MAX_LENGTH, USERNAME_PATTERN,
    SESSION_TIMEOUT, MAX_LOGIN_ATTEMPTS, ENCRYPTION_KEY_FILE, MFA_ISSUER, APP_NAME,
    EMAIL_HOST, EMAIL_PORT, EMAIL_USERNAME, EMAIL_PASSWORD, EMAIL_FROM,
    EMAIL_USE_TLS, EMAIL_CODE_EXPIRY
)

logger = logging.getLogger(__name__)

# ============================================================================
# ENCRYPTION FUNCTIONS (Defensive Measure #1 - Encryption)
# ============================================================================

def setup_encryption_key():
    """
    Initialize or load the encryption key from file.
    Uses Fernet symmetric encryption (AES-128-CBC with HMAC).
    """
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()
    
    # Generate new key
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(ENCRYPTION_KEY_FILE), exist_ok=True)
    
    # Save with restricted permissions
    with open(ENCRYPTION_KEY_FILE, 'wb') as f:
        f.write(key)
    os.chmod(ENCRYPTION_KEY_FILE, 0o600)
    
    logger.info("Encryption key generated and stored securely")
    return key


def get_encryption_cipher():
    """Get Fernet cipher instance for encryption/decryption."""
    key = setup_encryption_key()
    return Fernet(key)


def encrypt_data(data: str) -> str:
    """
    Encrypt sensitive data using Fernet symmetric encryption.
    
    Args:
        data: String data to encrypt
        
    Returns:
        Encrypted string (base64 encoded)
    """
    try:
        cipher = get_encryption_cipher()
        encrypted = cipher.encrypt(data.encode())
        return encrypted.decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise


def decrypt_data(encrypted_data: str) -> str:
    """
    Decrypt data encrypted with encrypt_data().
    
    Args:
        encrypted_data: Encrypted string
        
    Returns:
        Decrypted original string
    """
    try:
        cipher = get_encryption_cipher()
        decrypted = cipher.decrypt(encrypted_data.encode())
        return decrypted.decode()
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise


# ============================================================================
# PASSWORD FUNCTIONS (Defensive Measure #2 - Strong Authentication)
# ============================================================================

def hash_password(password: str) -> str:
    """
    Hash password using bcrypt with salt.
    Uses 12 salt rounds for strong security.
    
    Args:
        password: Plain text password
        
    Returns:
        Bcrypt hash with salt
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify password against bcrypt hash.
    
    Args:
        password: Plain text password to verify
        password_hash: Bcrypt hash to check against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception as e:
        logger.warning(f"Password verification error: {e}")
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password meets security requirements.
    
    OWASP A07 Mitigation: Enforce strong password policies
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not password:
        return False, "Password cannot be empty"
    
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long"
    
    if len(password) > PASSWORD_MAX_LENGTH:
        return False, f"Password must not exceed {PASSWORD_MAX_LENGTH} characters"
    
    if PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Password must contain at least one special character: !@#$%^&*()_+-=[]{}:;'\",./<>?\\|`~"
    
    # Check for common patterns that are weak
    weak_patterns = [
        r'(.)\1{2,}',  # Three or more repeating characters
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential chars
        r'(123|234|345|456|567|678|789|890)',  # Sequential numbers
    ]
    
    for pattern in weak_patterns:
        if re.search(pattern, password.lower()):
            return False, "Password contains common weak patterns"
    
    return True, ""


def validate_username(username: str) -> tuple[bool, str]:
    """
    Validate username meets requirements.
    
    Args:
        username: Username to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username cannot be empty"
    
    if len(username) < USERNAME_MIN_LENGTH:
        return False, f"Username must be at least {USERNAME_MIN_LENGTH} characters long"
    
    if len(username) > USERNAME_MAX_LENGTH:
        return False, f"Username must not exceed {USERNAME_MAX_LENGTH} characters"
    
    if not re.match(USERNAME_PATTERN, username):
        return False, f"Username can only contain letters, numbers, hyphens, and underscores"
    
    return True, ""


# ============================================================================
# MFA FUNCTIONS (Defensive Measure #1 - Multi-Factor Authentication)
# ============================================================================

def generate_mfa_secret(username: str) -> str:
    """
    Generate a TOTP secret for MFA.
    
    Args:
        username: Username for which to generate secret
        
    Returns:
        Base32 encoded secret
    """
    secret = pyotp.random_base32()
    logger.info(f"MFA secret generated for user: {username}")
    return secret


def get_totp(secret: str) -> pyotp.TOTP:
    """
    Get TOTP object for a secret.
    
    Args:
        secret: Base32 encoded TOTP secret
        
    Returns:
        pyotp.TOTP object
    """
    return pyotp.TOTP(secret, issuer_name=MFA_ISSUER)


def get_mfa_provisioning_uri(username: str, secret: str) -> str:
    """
    Get the provisioning URI for QR code generation.
    
    Args:
        username: Username
        secret: MFA secret
        
    Returns:
        otpauth:// URI for QR code
    """
    totp = get_totp(secret)
    return totp.provisioning_uri(name=username, issuer_name=MFA_ISSUER)


def verify_totp(secret: str, token: str) -> bool:
    """
    Verify TOTP token is valid for a secret.
    
    Args:
        secret: Base32 encoded TOTP secret
        token: 6-digit TOTP token to verify
        
    Returns:
        True if token is valid, False otherwise
    """
    try:
        token = str(token).strip()
        if not re.match(r'^\d{6}$', token):
            logger.warning(f"Invalid TOTP format: {token}")
            return False
        
        totp = get_totp(secret)
        # Check current and adjacent windows for clock skew tolerance
        is_valid = totp.verify(token, valid_window=1)
        
        if is_valid:
            logger.info("TOTP token verified successfully")
        else:
            logger.warning("TOTP token verification failed")
        
        return is_valid
    except Exception as e:
        logger.error(f"TOTP verification error: {e}")
        return False


# ============================================================================
# INPUT SANITIZATION (OWASP A03 - Injection Prevention)
# ============================================================================

def sanitize_input(user_input: str, max_length: int = 1000, allow_special: bool = False) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        user_input: Raw user input
        max_length: Maximum allowed length
        allow_special: Whether to allow special characters
        
    Returns:
        Sanitized string
    """
    if not isinstance(user_input, str):
        return ""
    
    # Trim whitespace
    sanitized = user_input.strip()
    
    # Enforce length limit
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    # Remove potential injection characters if special chars not allowed
    if not allow_special:
        # Remove common injection characters but allow spaces, hyphens, underscores, dots
        sanitized = re.sub(r'[<>"\';`\\(){}[\]|&$]', '', sanitized)
    
    # Remove null bytes (null injection)
    sanitized = sanitized.replace('\x00', '')
    
    # Normalize whitespace
    sanitized = ' '.join(sanitized.split())
    
    return sanitized


def validate_and_sanitize(data: dict, schema: dict) -> tuple[bool, dict, str]:
    """
    Validate and sanitize a dictionary of data against a schema.
    
    Schema format:
    {
        'field_name': {
            'type': str|int|float|list,
            'required': bool,
            'min_length': int (for strings and lists),
            'max_length': int,
            'pattern': regex (for strings),
            'min_value': number,
            'max_value': number,
        }
    }
    
    Args:
        data: Dictionary of user input
        schema: Validation schema
        
    Returns:
        Tuple of (is_valid, sanitized_data, error_message)
    """
    sanitized = {}
    
    for field_name, field_schema in schema.items():
        required = field_schema.get('required', False)
        field_value = data.get(field_name)
        
        # Check required fields
        if required and field_value is None:
            return False, {}, f"Field '{field_name}' is required"
        
        if field_value is None:
            continue
        
        # Type validation
        expected_type = field_schema.get('type', str)
        if not isinstance(field_value, expected_type):
            return False, {}, f"Field '{field_name}' must be of type {expected_type.__name__}"
        
        # String-specific validation
        if isinstance(field_value, str):
            field_value = sanitize_input(field_value, field_schema.get('max_length', 1000))
            
            min_len = field_schema.get('min_length', 0)
            max_len = field_schema.get('max_length', 1000)
            
            if len(field_value) < min_len:
                return False, {}, f"Field '{field_name}' must be at least {min_len} characters"
            
            if len(field_value) > max_len:
                return False, {}, f"Field '{field_name}' must not exceed {max_len} characters"
            
            # Pattern validation
            pattern = field_schema.get('pattern')
            if pattern and not re.match(pattern, field_value):
                return False, {}, f"Field '{field_name}' format is invalid"
        
        # List-specific validation
        elif isinstance(field_value, list):
            max_len = field_schema.get('max_length', 1000)
            if len(field_value) > max_len:
                return False, {}, f"Field '{field_name}' has too many items (max: {max_len})"
        
        # Number-specific validation
        elif isinstance(field_value, (int, float)):
            min_val = field_schema.get('min_value')
            max_val = field_schema.get('max_value')
            
            if min_val is not None and field_value < min_val:
                return False, {}, f"Field '{field_name}' must be at least {min_val}"
            
            if max_val is not None and field_value > max_val:
                return False, {}, f"Field '{field_name}' must not exceed {max_val}"
        
        sanitized[field_name] = field_value
    
    return True, sanitized, ""


# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

def generate_session_token() -> str:
    """Generate a secure random session token."""
    return secrets.token_urlsafe(32)


def create_session_id() -> str:
    """Create a unique session ID."""
    return secrets.token_hex(16)


# ============================================================================
# LOGGING AND AUDIT (OWASP A09 - Logging and Monitoring)
# ============================================================================

def log_security_event(event_type: str, username: str = None, details: str = None, severity: str = "INFO"):
    """
    Log security-related events for audit trail.
    
    Args:
        event_type: Type of event (LOGIN, FAILED_LOGIN, MFA_SETUP, PASSWORD_CHANGE, etc.)
        username: Username involved (if applicable)
        details: Additional details
        severity: Log level (INFO, WARNING, ERROR)
    """
    timestamp = datetime.utcnow().isoformat()
    message = f"[{timestamp}] {event_type}"
    if username:
        message += f" | User: {username}"
    if details:
        message += f" | Details: {details}"
    
    if severity == "WARNING":
        logger.warning(message)
    elif severity == "ERROR":
        logger.error(message)
    else:
        logger.info(message)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_session_expired(last_activity: datetime) -> bool:
    """
    Check if session has expired based on last activity.
    
    Args:
        last_activity: Datetime of last user activity
        
    Returns:
        True if session has expired, False otherwise
    """
    if not last_activity:
        return True
    
    elapsed = (datetime.utcnow() - last_activity).total_seconds()
    return elapsed > SESSION_TIMEOUT


def get_security_headers() -> dict:
    """
    Get recommended security headers for HTTP responses.
    
    Returns:
        Dictionary of security headers
    """
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    }


# ============================================================================
# EMAIL MFA FUNCTIONS
# ============================================================================

def generate_email_code() -> str:
    """
    Generate a 6-character alphanumeric code for email MFA.
    
    Returns:
        6-character code
    """
    return secrets.token_hex(3).upper()  # 6 characters


def send_email_mfa_code(email: str, code: str, username: str) -> bool:
    """
    Send MFA verification code via email.
    
    Args:
        email: Recipient email address
        code: Verification code
        username: Username for personalization
        
    Returns:
        True if email sent successfully
    """
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = email
        msg['Subject'] = f"{APP_NAME} - Your MFA Code"
        
        # Email body
        body = f"""
Hello {username},

Your Multi-Factor Authentication code for {APP_NAME} is:

{code}

This code will expire in 5 minutes. Please enter it to complete your login.

If you did not request this code, please ignore this email.

Best regards,
{APP_NAME} Security Team
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        if EMAIL_USE_TLS:
            server.starttls()
        
        if EMAIL_USERNAME and EMAIL_PASSWORD:
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        
        text = msg.as_string()
        server.sendmail(EMAIL_FROM, email, text)
        server.quit()
        
        logger.info(f"MFA email sent to {email} for user {username}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send MFA email to {email}: {e}")
        return False


__all__ = [
    'setup_encryption_key', 'encrypt_data', 'decrypt_data',
    'hash_password', 'verify_password', 'validate_password_strength',
    'validate_username', 'generate_mfa_secret', 'get_totp',
    'get_mfa_provisioning_uri', 'verify_totp',
    'sanitize_input', 'validate_and_sanitize',
    'generate_session_token', 'create_session_id',
    'log_security_event', 'is_session_expired', 'get_security_headers',
    'SESSION_TIMEOUT', 'MAX_LOGIN_ATTEMPTS', 'generate_email_code',
    'send_email_mfa_code'
]
