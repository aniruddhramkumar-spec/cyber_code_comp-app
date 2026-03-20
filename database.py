"""
Database module for ChartVault.
Implements secure user and graph management with prepared statements to prevent SQL injection.
"""

import sqlite3
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

from config import DATABASE_PATH, DATA_DIR

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_db_connection():
    """Get database connection with secure settings."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints
    return conn


def init_db():
    """Initialize database with secure schema (OWASP A01 - Access Control)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Users table with comprehensive security fields
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT,
                mfa_enabled BOOLEAN DEFAULT 0,
                mfa_secret TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                account_active BOOLEAN DEFAULT 1
            )
        """)
        
        # Graphs table with data integrity
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS graphs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                graph_name TEXT NOT NULL COLLATE NOCASE,
                graph_type TEXT NOT NULL,
                title TEXT,
                description TEXT,
                graph_data TEXT NOT NULL,
                parameters TEXT NOT NULL,
                is_public BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                deleted_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, graph_name)
            )
        """)
        
        # Audit log for security monitoring (OWASP A09 - Logging)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id INTEGER,
                details TEXT,
                status TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        
        # Sessions table for session management
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_id TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes for better performance and query optimization
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_graphs_user_id ON graphs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_graphs_type ON graphs(graph_type)")
        
        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise
    finally:
        conn.close()


# ============================================================================
# USER MANAGEMENT FUNCTIONS
# ============================================================================

def create_user(username: str, password_hash: str, email: str, full_name: str = "") -> Optional[int]:
    """
    Create a new user with hashed password.
    Uses parameterized queries to prevent SQL injection (OWASP A03).
    
    Args:
        username: Username
        password_hash: Bcrypt hashed password
        email: Email address
        full_name: User's full name
        
    Returns:
        User ID if successful, None if failed
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """INSERT INTO users (username, password_hash, email, full_name) 
               VALUES (?, ?, ?, ?)""",
            (username, password_hash, email, full_name)
        )
        conn.commit()
        user_id = cursor.lastrowid
        log_audit("user_created", user_id, "User", user_id, "User account created")
        logger.info(f"User {username} created successfully")
        return user_id
    except sqlite3.IntegrityError as e:
        logger.warning(f"User creation failed - duplicate: {e}")
        return None
    except Exception as e:
        logger.error(f"User creation error: {e}")
        return None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict]:
    """
    Retrieve user by username using parameterized query.
    Prevents SQL injection (OWASP A03).
    
    Args:
        username: Username to retrieve
        
    Returns:
        User dictionary or None
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND account_active = 1",
            (username,)
        )
        user = cursor.fetchone()
        return dict(user) if user else None
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[Dict]:
    """Get user by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM users WHERE id = ? AND account_active = 1", (user_id,))
        user = cursor.fetchone()
        return dict(user) if user else None
    except Exception as e:
        logger.error(f"Error fetching user by ID: {e}")
        return None
    finally:
        conn.close()


def user_exists(username: str, email: str = None) -> bool:
    """Check if user already exists."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email or ""))
        return cursor.fetchone() is not None
    except Exception as e:
        logger.error(f"Error checking user existence: {e}")
        return True  # Default to True to be safe
    finally:
        conn.close()


# ============================================================================
# GRAPH MANAGEMENT FUNCTIONS
# ============================================================================

def save_graph(user_id: int, graph_name: str, graph_type: str, 
               title: str, description: str, graph_data: str, 
               parameters: Dict) -> Optional[int]:
    """
    Save graph data securely with ownership binding.
    
    Args:
        user_id: Owner user ID
        graph_name: Graph name
        graph_type: Type of graph
        title: Chart title
        description: Chart description
        graph_data: Serialized graph data (JSON encrypted)
        parameters: Parameters dictionary
        
    Returns:
        Graph ID if successful, None if failed
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        params_json = json.dumps(parameters)
        cursor.execute(
            """INSERT INTO graphs (user_id, graph_name, graph_type, title, description, graph_data, parameters)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, graph_name, graph_type, title, description, graph_data, params_json)
        )
        conn.commit()
        graph_id = cursor.lastrowid
        log_audit("graph_created", user_id, "Graph", graph_id, f"Created graph: {graph_name}")
        return graph_id
    except sqlite3.IntegrityError:
        # Handle duplicate graph name - update instead
        return update_graph(user_id, graph_name, graph_type, title, description, graph_data, parameters)
    except Exception as e:
        logger.error(f"Graph save error: {e}")
        return None
    finally:
        conn.close()


def update_graph(user_id: int, graph_name: str, graph_type: str,
                 title: str, description: str, graph_data: str,
                 parameters: Dict) -> Optional[int]:
    """
    Update an existing graph.
    
    Returns:
        Graph ID if successful
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        params_json = json.dumps(parameters)
        cursor.execute(
            """UPDATE graphs 
               SET graph_type = ?, title = ?, description = ?, graph_data = ?, parameters = ?, updated_at = CURRENT_TIMESTAMP
               WHERE user_id = ? AND graph_name = ? AND deleted_at IS NULL""",
            (graph_type, title, description, graph_data, params_json, user_id, graph_name)
        )
        conn.commit()
        
        # Get the graph ID
        cursor.execute("SELECT id FROM graphs WHERE user_id = ? AND graph_name = ?", (user_id, graph_name))
        result = cursor.fetchone()
        if result:
            graph_id = result[0]
            log_audit("graph_updated", user_id, "Graph", graph_id, f"Updated graph: {graph_name}")
            return graph_id
        return None
    except Exception as e:
        logger.error(f"Graph update error: {e}")
        return None
    finally:
        conn.close()


def get_user_graphs(user_id: int) -> List[Dict]:
    """
    Get all graphs for a user with ownership verification (OWASP A01).
    
    Args:
        user_id: User ID
        
    Returns:
        List of graph dictionaries
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """SELECT id, graph_name, graph_type, title, description, created_at, updated_at 
               FROM graphs WHERE user_id = ? AND deleted_at IS NULL
               ORDER BY updated_at DESC""",
            (user_id,)
        )
        graphs = [dict(row) for row in cursor.fetchall()]
        return graphs
    except Exception as e:
        logger.error(f"Error fetching graphs: {e}")
        return []
    finally:
        conn.close()


def get_graph(graph_id: int, user_id: int) -> Optional[Dict]:
    """
    Get specific graph with ownership verification (OWASP A01 - Access Control).
    
    Args:
        graph_id: Graph ID
        user_id: User ID (for ownership check)
        
    Returns:
        Graph dictionary or None
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """SELECT * FROM graphs 
               WHERE id = ? AND user_id = ? AND deleted_at IS NULL""",
            (graph_id, user_id)
        )
        graph = cursor.fetchone()
        return dict(graph) if graph else None
    except Exception as e:
        logger.error(f"Error fetching graph: {e}")
        return None
    finally:
        conn.close()


def delete_graph(graph_id: int, user_id: int) -> bool:
    """
    Delete graph with ownership verification (soft delete for audit trail).
    
    Args:
        graph_id: Graph ID
        user_id: User ID (for ownership check)
        
    Returns:
        True if successful, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """UPDATE graphs SET deleted_at = CURRENT_TIMESTAMP 
               WHERE id = ? AND user_id = ? AND deleted_at IS NULL""",
            (graph_id, user_id)
        )
        conn.commit()
        if cursor.rowcount > 0:
            log_audit("graph_deleted", user_id, "Graph", graph_id, "Graph deleted")
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting graph: {e}")
        return False
    finally:
        conn.close()


# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

def update_user_mfa(user_id: int, mfa_secret: str, enabled: bool = True) -> bool:
    """
    Update MFA settings for user (OWASP A07 - Authentication Failures).
    
    Args:
        user_id: User ID
        mfa_secret: TOTP secret
        enabled: Enable or disable MFA
        
    Returns:
        True if successful
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """UPDATE users SET mfa_enabled = ?, mfa_secret = ?, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (enabled, mfa_secret if enabled else None, user_id)
        )
        conn.commit()
        log_audit("mfa_updated", user_id, "User", user_id, f"MFA enabled: {enabled}")
        return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"MFA update error: {e}")
        return False
    finally:
        conn.close()


def update_password(user_id: int, new_password_hash: str) -> bool:
    """
    Update user password.
    
    Args:
        user_id: User ID
        new_password_hash: New bcrypt hashed password
        
    Returns:
        True if successful
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """UPDATE users 
               SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (new_password_hash, user_id)
        )
        conn.commit()
        log_audit("password_changed", user_id, "User", user_id, "Password changed")
        return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Password update error: {e}")
        return False
    finally:
        conn.close()


def update_last_login(user_id: int) -> bool:
    """Update last login timestamp."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Last login update error: {e}")
        return False
    finally:
        conn.close()


def increment_failed_login(username: str) -> int:
    """
    Increment failed login attempts for account lockout (OWASP A07).
    
    Args:
        username: Username
        
    Returns:
        Number of failed login attempts
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """UPDATE users SET failed_login_attempts = failed_login_attempts + 1 
               WHERE username = ?""",
            (username,)
        )
        conn.commit()
        
        cursor.execute("SELECT failed_login_attempts FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result[0] if result else 0
    except Exception as e:
        logger.error(f"Failed login increment error: {e}")
        return 0
    finally:
        conn.close()


def reset_failed_login(user_id: int) -> bool:
    """Reset failed login attempts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Reset failed login error: {e}")
        return False
    finally:
        conn.close()


def lock_account(username: str, duration_seconds: int = 900) -> bool:
    """
    Lock account after too many failed login attempts (OWASP A07).
    
    Args:
        username: Username to lock
        duration_seconds: Lock duration in seconds
        
    Returns:
        True if successful
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        locked_until = datetime.utcnow() + timedelta(seconds=duration_seconds)
        cursor.execute(
            "UPDATE users SET locked_until = ? WHERE username = ?",
            (locked_until, username)
        )
        conn.commit()
        log_audit(None, None, "Security", None, f"Account locked: {username}")
        return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Account lock error: {e}")
        return False
    finally:
        conn.close()


def is_account_locked(username: str) -> bool:
    """Check if account is currently locked."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT locked_until FROM users WHERE username = ?",
            (username,)
        )
        result = cursor.fetchone()
        if not result or not result[0]:
            return False
        
        locked_until = datetime.fromisoformat(result[0])
        if datetime.utcnow() > locked_until:
            # Lock has expired, reset it
            reset_failed_login(None)
            return False
        return True
    except Exception as e:
        logger.error(f"Account lock check error: {e}")
        return False
    finally:
        conn.close()


# ============================================================================
# SESSION MANAGEMENT FUNCTIONS
# ============================================================================

def create_session(user_id: int, session_id: str, expires_in_seconds: int = 1800) -> bool:
    """Create a new session."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in_seconds)
        cursor.execute(
            """INSERT INTO sessions (user_id, session_id, expires_at)
               VALUES (?, ?, ?)""",
            (user_id, session_id, expires_at)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Session creation error: {e}")
        return False
    finally:
        conn.close()


def get_session(session_id: str) -> Optional[Dict]:
    """Get session information."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """SELECT * FROM sessions 
               WHERE session_id = ? AND expires_at > datetime('now')""",
            (session_id,)
        )
        session = cursor.fetchone()
        return dict(session) if session else None
    except Exception as e:
        logger.error(f"Session fetch error: {e}")
        return None
    finally:
        conn.close()


def delete_session(session_id: str) -> bool:
    """Delete a session (logout)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Session deletion error: {e}")
        return False
    finally:
        conn.close()


def update_session_activity(session_id: str) -> bool:
    """Update last activity timestamp for session."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = ?",
            (session_id,)
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Session activity update error: {e}")
        return False
    finally:
        conn.close()


# ============================================================================
# AUDIT LOGGING FUNCTIONS (OWASP A09 - Logging and Monitoring)
# ============================================================================

def log_audit(action: str, user_id: Optional[int] = None, resource_type: str = None, 
              resource_id: Optional[int] = None, details: str = None, status: str = "SUCCESS"):
    """
    Log security audit events for monitoring and forensics.
    
    Args:
        action: Action being logged
        user_id: User ID performing action
        resource_type: Type of resource affected
        resource_id: ID of resource affected
        details: Additional details
        status: Status of action (SUCCESS, FAILURE, etc.)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, status) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, action, resource_type, resource_id, details, status)
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Audit log error: {e}")
    finally:
        conn.close()


def get_audit_log(user_id: Optional[int] = None, limit: int = 100) -> List[Dict]:
    """Get audit log entries."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if user_id:
            cursor.execute(
                """SELECT * FROM audit_log WHERE user_id = ? 
                   ORDER BY timestamp DESC LIMIT ?""",
                (user_id, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
        entries = [dict(row) for row in cursor.fetchall()]
        return entries
    except Exception as e:
        logger.error(f"Audit log fetch error: {e}")
        return []
    finally:
        conn.close()


__all__ = [
    'init_db', 'get_db_connection', 'create_user', 'get_user_by_username', 
    'get_user_by_id', 'user_exists', 'save_graph', 'update_graph',
    'get_user_graphs', 'get_graph', 'delete_graph', 'update_user_mfa',
    'update_password', 'update_last_login', 'increment_failed_login',
    'reset_failed_login', 'lock_account', 'is_account_locked',
    'create_session', 'get_session', 'delete_session', 'update_session_activity',
    'log_audit', 'get_audit_log'
]
