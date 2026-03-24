"""
ChartVault - Secure Graph Generator Application
Professional data visualization platform with enterprise-grade security.

Features:
- User authentication with MFA (TOTP)
- AES-256 encryption for stored graphs
- Input validation and sanitization
- Audit logging
- Session management with timeout
- Account lockout protection
- Professional responsive UI
"""

import streamlit as st
from streamlit import session_state as ss
import json
from datetime import datetime, timedelta
import logging
import qrcode
from io import BytesIO
import base64

# Import custom modules
from database import (
    init_db, create_user, get_user_by_username, get_user_by_id,
    user_exists, save_graph, update_graph, get_user_graphs, get_graph,
    delete_graph, update_user_mfa, update_password, update_last_login,
    increment_failed_login, reset_failed_login, lock_account, is_account_locked,
    create_session, get_session, delete_session, update_session_activity, log_audit,
    create_email_verification_code, verify_email_code, cleanup_expired_codes
)
from security import (
    setup_encryption_key, hash_password, verify_password,
    generate_mfa_secret, verify_totp, sanitize_input,
    validate_password_strength, validate_username, SESSION_TIMEOUT,
    MAX_LOGIN_ATTEMPTS, get_totp, get_mfa_provisioning_uri,
    encrypt_data, decrypt_data, log_security_event, create_session_id,
    generate_email_code, send_email_mfa_code
)
from validators import (
    validate_chart_title, validate_axis_label, validate_graph_name,
    validate_description, validate_number_list, validate_category_list,
    validate_proportions, validate_histogram_bins, sanitize_dict,
    validate_line_graph_data, validate_scatter_plot_data,
    validate_bar_chart_data, validate_pie_chart_data,
    validate_histogram_data, validate_box_whisker_data
)
from graphs import (
    create_line_graph, create_scatter_plot, create_histogram,
    create_pie_chart, create_box_whisker_plot, serialize_graph, deserialize_graph
)
from config import (
    APP_NAME, APP_VERSION, APP_DESCRIPTION, SESSION_TIMEOUT,
    MAX_LOGIN_ATTEMPTS, COLORS, LOCKOUT_DURATION
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title=f"{APP_NAME} - Secure Graph Generator",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "About": f"{APP_NAME} v{APP_VERSION}\n\n{APP_DESCRIPTION}\n\nContact: support@chartvault.com"
    }
)

# Initialize database and encryption
init_db()
setup_encryption_key()

# ============================================================================
# CUSTOM CSS AND STYLING
# ============================================================================

st.markdown(f"""
<style>
    /* Root colors */
    :root {{
        --primary: {COLORS['primary']};
        --secondary: {COLORS['secondary']};
        --success: {COLORS['success']};
        --warning: {COLORS['warning']};
        --danger: {COLORS['danger']};
        --light-bg: {COLORS['light_bg']};
        --border: {COLORS['border']};
    }}
    
    /* Main container */
    .main {{
        background-color: {COLORS['light_bg']};
        font-family: 'Courier New', Courier, monospace !important;
    }}
    
    /* Global Courier typewriter-style font for all text */
    html, body, * {{
        font-family: 'Courier New', Courier, monospace !important;
    }}
    
    /* Dashboard specific background */
    .dashboard-bg {{
        background-color: #87CEEB !important; /* Light cornflower blue */
    }}
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {{
        background-color: {COLORS['sidebar_bg']};
        border-right: 2px solid {COLORS['border']};
    }}
    
    /* Header styling */
    .header {{
        background: #F0E6FF !important; /* Pale lavender */
        color: #4B0082; /* Dark purple text for contrast */
        padding: 30px;
        border-radius: 10px;
        margin-bottom: 30px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }}
    
    .header h1 {{
        margin: 0;
        font-size: 2.5em;
        font-weight: 700;
        text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    }}
    
    .header p {{
        margin: 5px 0 0 0;
        font-size: 1.1em;
        opacity: 0.95;
    }}
    
    /* Login page header styling - dark green text */
    .login-header {{
        background: #F0E6FF !important; /* Pale lavender */
        color: #006400 !important; /* Dark green text */
    }}
    
    .login-header h1 {{
        color: #006400 !important; /* Dark green for title */
    }}
    
    .login-header p {{
        color: #006400 !important; /* Dark green for subtitle */
        opacity: 0.8 !important;
    }}
    
    /* Account page header styling - deep brown background with light cream text */
    .account-header {{
        background: #654321 !important; /* Deep brown */
        color: #F5DEB3 !important; /* Light cream text */
    }}
    
    .account-header h1 {{
        color: #F5DEB3 !important; /* Light cream for title */
    }}
    
    .account-header p {{
        color: #F5DEB3 !important; /* Light cream for subtitle */
        opacity: 0.8 !important;
    }}
    
    /* Card styling */
    .card {{
        background: {COLORS['card_bg']};
        border-radius: 12px;
        padding: 25px;
        border: 1px solid {COLORS['border']};
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        margin-bottom: 20px;
        transition: all 0.3s ease;
    }}
    
    .card:hover {{
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
        border-color: {COLORS['secondary']};
    }}
    
    /* Button styling */
    .stButton > button {{
        background: linear-gradient(135deg, {COLORS['secondary']} 0%, {COLORS['primary']} 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 12px 24px;
        font-weight: 600;
        font-size: 1em;
        transition: all 0.3s ease;
        width: 100%;
    }}
    
    .stButton > button:hover {{
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(58, 130, 246, 0.4);
    }}
    
    /* Input styling */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stTextArea > div > div > textarea {{
        border: 1.5px solid {COLORS['border']} !important;
        border-radius: 8px !important;
        padding: 12px !important;
        font-size: 1em !important;
    }}
    
    .stTextInput > div > div > input:focus,
    .stNumberInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {{
        border-color: {COLORS['secondary']} !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1) !important;
    }}
    
    /* Alert styling */
    .stAlert {{
        border-radius: 8px;
        padding: 15px;
        margin: 15px 0;
    }}
    
    .success {{
        background-color: #FFE5CC;
        border-left: 4px solid {COLORS['success']};
        color: #065F46;
    }}
    
    .error {{
        background-color: #FFCC99;
        border-left: 4px solid {COLORS['danger']};
        color: #7F1D1D;
    }}
    
    .warning {{
        background-color: #FFD4A3;
        border-left: 4px solid {COLORS['warning']};
        color: #78350F;
    }}
    
    .info {{
        background-color: #FFE0B2;
        border-left: 4px solid {COLORS['info']};
        color: #0C2340;
    }}
    
    /* Tab styling */
    .stTabs {{
        background-color: {COLORS['tab_bg']};
        border-radius: 12px;
        padding: 20px;
        border: 1px solid {COLORS['border']};
    }}
    
    /* Text styling */
    h1, h2, h3 {{
        color: {COLORS['primary']};
        font-weight: 700;
    }}
    
    p {{
        color: {COLORS['text_secondary']};
        line-height: 1.6;
    }}
    
    /* Badge styling */
    .badge {{
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.85em;
        font-weight: 600;
        background-color: {COLORS['light_bg']};
        color: {COLORS['primary']};
        border: 1px solid {COLORS['border']};
    }}
    
    .badge.success {{
        background-color: #FFE5CC;
        color: {COLORS['success']};
        border-color: {COLORS['success']};
    }}
    
    .badge.warning {{
        background-color: #FFD4A3;
        color: {COLORS['warning']};
        border-color: {COLORS['warning']};
    }}
    
    .badge.danger {{
        background-color: #FFCC99;
        color: {COLORS['danger']};
        border-color: {COLORS['danger']};
    }}
    
    /* Responsive adjustments */
    @media (max-width: 768px) {{
        .header h1 {{
            font-size: 1.8em;
        }}
        
        .stButton > button {{
            padding: 10px 16px;
            font-size: 0.9em;
        }}
    }}
</style>
""", unsafe_allow_html=True)

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

def init_session_state():
    """Initialize all required session state variables."""
    defaults = {
        'authenticated': False,
        'user_id': None,
        'username': None,
        'session_id': None,
        'mfa_enabled': False,
        'mfa_setup_required': False,
        'mfa_secret_temp': None,
        'current_page': 'login',
        'page_history': [],
        'last_activity': datetime.utcnow(),
        'show_success': False,
        'show_error': False,
        'error_message': '',
        'success_message': '',
        'selected_graph_id': None,
        'graph_to_edit': None,
    }
    
    for key, value in defaults.items():
        if key not in ss:
            ss[key] = value


init_session_state()

# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

def check_session_expiry():
    """Check if user session has expired and handle logout."""
    if ss.authenticated:
        elapsed = (datetime.utcnow() - ss.last_activity).total_seconds()
        if elapsed > SESSION_TIMEOUT:
            logout()
            st.warning(f"⏱️ Your session expired due to inactivity. Please log in again.")
            st.stop()
    
    ss.last_activity = datetime.utcnow()


def register_user(username: str, email: str, password: str, confirm_password: str) -> tuple[bool, str]:
    """
    Register a new user with validation.
    
    Returns:
        Tuple of (success, message)
    """
    # Validate input
    if password != confirm_password:
        return False, "Passwords do not match"
    
    # Validate username
    is_valid, error = validate_username(username)
    if not is_valid:
        return False, f"Invalid username: {error}"
    
    # Validate password strength
    is_valid, error = validate_password_strength(password)
    if not is_valid:
        return False, f"Weak password: {error}"
    
    # Check if user already exists
    if user_exists(username, email):
        return False, "Username or email already in use"
    
    try:
        # Hash password and create user
        password_hash = hash_password(password)
        user_id = create_user(username, password_hash, email)
        
        if user_id:
            log_security_event("user_registered", username, f"New user account created")
            logger.info(f"New user registered: {username}")
            return True, f"Account created successfully. Please log in."
        else:
            logger.error(f"Failed to create user: {username}")
            return False, "Failed to create account. Please try again."
    
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return False, f"Registration error: {str(e)[:50]}"


def login_user(username: str, password: str, mfa_code: str = None) -> tuple[bool, str]:
    """
    Authenticate user with MFA support.
    
    Returns:
        Tuple of (success, message)
    """
    try:
        # Check account lockout
        if is_account_locked(username):
            log_security_event("login_blocked", username, "Account is temporarily locked")
            return False, "Account temporarily locked due to too many failed login attempts. Try again later."
        
        # Get user
        user = get_user_by_username(username)
        if not user:
            increment_failed_login(username)
            log_security_event("login_failed", username, "Invalid username")
            return False, "Invalid username or password"
        
        # Verify password
        if not verify_password(password, user['password_hash']):
            attempts = increment_failed_login(username)
            log_security_event("login_failed", username, f"Invalid password (attempt {attempts})")
            
            if attempts >= MAX_LOGIN_ATTEMPTS:
                lock_account(username, LOCKOUT_DURATION)
                log_security_event("account_locked", username, "Too many failed login attempts")
                return False, f"Account locked after {MAX_LOGIN_ATTEMPTS} failed attempts. Try again in 15 minutes."
            
            return False, f"Invalid username or password ({MAX_LOGIN_ATTEMPTS - attempts} attempts remaining)"
        
        # Check MFA if enabled
        if user['mfa_enabled']:
            if not mfa_code:
                return False, "mfa_required"
            
            mfa_type = user.get('mfa_type', 'totp')
            if mfa_type == 'email':
                if not verify_email_code(user['id'], mfa_code, 'mfa_login'):
                    log_security_event("mfa_failed", username, "Invalid email MFA code")
                    return False, "Invalid MFA code"
            else:  # totp
                if not verify_totp(user['mfa_secret'], mfa_code):
                    log_security_event("mfa_failed", username, "Invalid TOTP MFA code")
                    return False, "Invalid MFA code"
        
        # Successful login
        reset_failed_login(user['id'])
        update_last_login(user['id'])
        
        # Create session
        session_id = create_session_id()
        create_session(user['id'], session_id)
        
        # Update session state
        ss.authenticated = True
        ss.user_id = user['id']
        ss.username = username
        ss.session_id = session_id
        ss.mfa_enabled = user['mfa_enabled']
        ss.mfa_type = user.get('mfa_type', 'totp')
        ss.last_activity = datetime.utcnow()
        ss.current_page = 'dashboard'
        
        log_security_event("login_success", username, f"User logged in")
        logger.info(f"User logged in: {username}")
        
        return True, f"Welcome back, {username}! 👋"
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        return False, f"Login error: {str(e)[:50]}"


def logout():
    """Logout current user."""
    if ss.authenticated and ss.username:
        if ss.session_id:
            delete_session(ss.session_id)
        log_security_event("logout", ss.username, "User logged out")
        logger.info(f"User logged out: {ss.username}")
    
    # Reset session state
    ss.authenticated = False
    ss.user_id = None
    ss.username = None
    ss.session_id = None
    ss.mfa_enabled = False
    ss.mfa_type = None
    ss.current_page = 'login'
    ss.selected_graph_id = None


def setup_mfa():
    """Setup MFA for user."""
    user = get_user_by_id(ss.user_id)
    if not user:
        st.error("User not found")
        return
    
    st.info("🔐 Multi-Factor Authentication Setup")
    st.write("""
    Multi-factor authentication adds an extra layer of security to your account.
    Choose your preferred method below.
    """)
    
    # Choose MFA type
    mfa_type = st.radio(
        "Select MFA Method:",
        ["TOTP (Authenticator App)", "Email"],
        key="mfa_type_radio",
        help="TOTP uses an authenticator app, Email sends codes to your email address"
    )
    
    if mfa_type == "TOTP (Authenticator App)":
        setup_totp_mfa(user)
    else:
        setup_email_mfa(user)


def setup_totp_mfa(user):
    """Setup TOTP MFA."""
    if not ss.mfa_secret_temp:
        ss.mfa_secret_temp = generate_mfa_secret(ss.username)
    
    st.write("**TOTP Setup:** Use an authenticator app like Google Authenticator or Authy.")
    
    # Display QR code
    provisioning_uri = get_mfa_provisioning_uri(ss.username, ss.mfa_secret_temp)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color=COLORS["light_bg"])
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    
    col1, col2 = st.columns(2)
    with col1:
        st.image(buf, caption="Scan with authenticator app", width=300)
    
    with col2:
        st.write("**Or enter this code manually:**")
        st.code(ss.mfa_secret_temp, language=None)
    
    # Verify MFA code
    st.divider()
    st.write("**Verify your authenticator app:**")
    mfa_code = st.text_input("Enter 6-digit code from app:", max_chars=6, type="password", key="totp_code")
    
    if st.button("✓ Confirm TOTP Setup", use_container_width=True):
        if not mfa_code or len(mfa_code) != 6:
            st.error("Please enter a valid 6-digit code")
        elif verify_totp(ss.mfa_secret_temp, mfa_code):
            # Save MFA secret
            update_user_mfa(ss.user_id, ss.mfa_secret_temp, True, 'totp')
            ss.mfa_enabled = True
            ss.mfa_secret_temp = None
            log_security_event("mfa_enabled", ss.username, "TOTP MFA enabled for account")
            st.success("✓ TOTP MFA setup complete! Your account is now more secure.")
            st.rerun()
        else:
            st.error("Invalid code. Please try again.")


def setup_email_mfa(user):
    """Setup Email MFA."""
    st.write("**Email Setup:** We'll send verification codes to your email address.")
    st.write(f"**Email:** {user['email']}")
    
    if st.button("📧 Send Test Code", use_container_width=True):
        # Generate and send test code
        code = generate_email_code()
        if create_email_verification_code(ss.user_id, code, 'mfa_setup'):
            if send_email_mfa_code(user['email'], code, ss.username):
                st.success("Test code sent! Check your email.")
                ss.email_test_sent = True
                st.rerun()
            else:
                st.error("Failed to send email. Please check your email configuration.")
        else:
            st.error("Failed to generate verification code.")
    
    if ss.email_test_sent:
        st.divider()
        st.write("**Verify your email:**")
        mfa_code = st.text_input("Enter 6-character code from email:", max_chars=6, type="password", key="email_code")
        
        if st.button("✓ Confirm Email MFA Setup", use_container_width=True):
            if not mfa_code or len(mfa_code) != 6:
                st.error("Please enter a valid 6-character code")
            elif verify_email_code(ss.user_id, mfa_code, 'mfa_setup'):
                # Enable email MFA (no secret needed)
                update_user_mfa(ss.user_id, None, True, 'email')
                ss.mfa_enabled = True
                ss.email_test_sent = False
                log_security_event("mfa_enabled", ss.username, "Email MFA enabled for account")
                st.success("✓ Email MFA setup complete! Your account is now more secure.")
                st.rerun()
            else:
                st.error("Invalid code. Please try again.")


# ============================================================================
# GRAPH MANAGEMENT FUNCTIONS
# ============================================================================

def create_and_save_graph(graph_type: str, graph_name: str, title: str,
                         description: str, params: dict) -> tuple[bool, str]:
    """
    Create graph and save encrypted data to database.
    
    Returns:
        Tuple of (success, message)
    """
    try:
        # Validate graph name
        is_valid, error = validate_graph_name(graph_name)
        if not is_valid:
            return False, f"Invalid graph name: {error}"
        
        # Validate title
        is_valid, error = validate_chart_title(title)
        if not is_valid:
            return False, f"Invalid title: {error}"
        
        # Create appropriate graph based on type
        success, fig, error_msg = None, None, ""
        
        if graph_type == "Line Graph":
            success, error_msg, x_data = validate_number_list(params.get('x_values', []))
            if success:
                y_valid, y_error, y_data = validate_number_list(params.get('y_values', []))
                success = y_valid
                error_msg = y_error if not y_valid else error_msg
        
        if graph_type == "Line Graph":
            x_valid, x_error, x_data = validate_number_list(params.get('x_values', []))
            y_valid, y_error, y_data = validate_number_list(params.get('y_values', []))
            
            if not x_valid or not y_valid:
                return False, f"Invalid data: {x_error or y_error}"
            
            success, fig, error_msg = create_line_graph(
                x_data, y_data, title,
                params.get('x_label', 'X'),
                params.get('y_label', 'Y')
            )
        
        elif graph_type == "Scatter Plot":
            x_valid, x_error, x_data = validate_number_list(params.get('x_values', []))
            y_valid, y_error, y_data = validate_number_list(params.get('y_values', []))
            
            if not x_valid or not y_valid:
                return False, f"Invalid data: {x_error or y_error}"
            
            success, fig, error_msg = create_scatter_plot(
                x_data, y_data, title,
                params.get('x_label', 'X'),
                params.get('y_label', 'Y')
            )
        
        elif graph_type == "Histogram":
            data_valid, data_error, data = validate_number_list(params.get('data', []))
            if not data_valid:
                return False, f"Invalid data: {data_error}"
            
            success, fig, error_msg = create_histogram(
                data, title,
                params.get('x_label', 'Value'),
                params.get('y_label', 'Frequency'),
                params.get('bins', 30)
            )
        
        elif graph_type == "Pie Chart":
            labels_valid, labels_error, labels = validate_category_list(params.get('labels', []))
            props_valid, props_error, props = validate_proportions(params.get('proportions', []))
            
            if not labels_valid or not props_valid:
                return False, f"Invalid data: {labels_error or props_error}"
            
            success, fig, error_msg = create_pie_chart(labels, props, title)
        
        elif graph_type == "Box-and-Whisker Plot":
            labels_valid, labels_error, labels = validate_category_list(params.get('labels', []))
            if not labels_valid:
                return False, f"Invalid labels: {labels_error}"
            
            # Parse box data (groups separated by |)
            data_groups = {}
            data_input = params.get('data', '')
            if isinstance(data_input, str):
                groups = data_input.split('|')
                for i, group in enumerate(groups):
                    if i < len(labels):
                        valid, error, data = validate_number_list(group)
                        if valid:
                            data_groups[labels[i]] = data
            
            if not data_groups:
                return False, "No valid data for box plot"
            
            success, fig, error_msg = create_box_whisker_plot(
                data_groups, title,
                params.get('y_label', 'Value')
            )
        
        else:
            return False, f"Unknown graph type: {graph_type}"
        
        if not success or fig is None:
            return False, f"Failed to create graph: {error_msg}"
        
        # Serialize and encrypt graph
        ser_success, graph_json = serialize_graph(fig)
        if not ser_success:
            return False, "Failed to serialize graph"
        
        encrypted_data = encrypt_data(graph_json)
        
        # Save to database
        sanitized_params = sanitize_dict(params)
        graph_id = save_graph(
            ss.user_id, graph_name, graph_type, title, description,
            encrypted_data, sanitized_params
        )
        
        if graph_id:
            log_audit("graph_created", ss.user_id, "Graph", graph_id, f"Created: {graph_name}")
            return True, f"Graph '{graph_name}' saved successfully! 📊"
        else:
            return False, "Failed to save graph to database"
    
    except Exception as e:
        logger.error(f"Graph creation error: {e}")
        return False, f"Error: {str(e)[:100]}"


# ============================================================================
# UI PAGES
# ============================================================================

def page_login():
    """Login/Register page."""
    st.markdown(f"""
    <div class="header login-header">
        <h1>📊 {APP_NAME}</h1>
        <p>Secure Data Visualization Platform</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["🔓 Login", "📝 Register"])
    
    with tab1:
        st.subheader("Login to Your Account")
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            col_login, col_pass = st.columns(2)
            with col_login:
                submitted = st.form_submit_button("🔓 Login", use_container_width=True)
            with col_pass:
                st.write("")  # Spacing
            
            if submitted:
                if not username or not password:
                    st.error("Please enter both username and password")
                else:
                    success, message = login_user(username, password)
                    if message == "mfa_required":
                        ss.username_temp = username
                        ss.password_temp = password
                        st.session_state['mfa_required'] = True
                        st.rerun()
                    elif success:
                        st.success(message)
                        st.balloons()
                        st.rerun()
                    else:
                        st.error(message)
        
        # MFA code entry if needed
        if ss.get('mfa_required', False):
            st.divider()
            user = get_user_by_username(ss.username_temp)
            mfa_type = user.get('mfa_type', 'totp') if user else 'totp'
            
            if mfa_type == 'email':
                st.info("🔐 We've sent a 6-character code to your email. Enter it below:")
                if not ss.get('mfa_email_sent', False):
                    # Send email code
                    code = generate_email_code()
                    if create_email_verification_code(user['id'], code, 'mfa_login'):
                        if send_email_mfa_code(user['email'], code, ss.username_temp):
                            ss.mfa_email_sent = True
                            st.success("Code sent to your email!")
                        else:
                            st.error("Failed to send email. Please try logging in again.")
                    else:
                        st.error("Failed to generate verification code.")
                
                code_input = st.text_input("6-character code", max_chars=6, type="password", key="mfa_code")
            else:
                st.info("🔐 Enter your 6-digit code from your authenticator app:")
                code_input = st.text_input("6-digit code", max_chars=6, type="password", key="mfa_code")
            
            if st.button("✓ Verify MFA", use_container_width=True):
                success, message = login_user(ss.username_temp, ss.password_temp, code_input)
                if success:
                    st.success(message)
                    st.balloons()
                    ss['mfa_required'] = False
                    ss.mfa_email_sent = False
                    st.rerun()
                else:
                    st.error(message)
    
    with tab2:
        st.subheader("Create a New Account")
        with st.form("register_form"):
            reg_username = st.text_input("Username", placeholder="3-32 characters (letters, numbers, -, _)")
            reg_email = st.text_input("Email", placeholder="your@email.com")
            reg_password = st.text_input("Password", type="password", placeholder="12+ characters with mixed case, numbers, special chars")
            reg_confirm = st.text_input("Confirm Password", type="password", placeholder="Re-enter your password")
            
            col_reg, col_reset = st.columns(2)
            with col_reg:
                reg_submitted = st.form_submit_button("📝 Create Account", use_container_width=True)
            
            if reg_submitted:
                if not all([reg_username, reg_email, reg_password, reg_confirm]):
                    st.error("Please fill all fields")
                else:
                    success, message = register_user(reg_username, reg_email, reg_password, reg_confirm)
                    if success:
                        st.success(message)
                        st.info("You can now log in with your username and password")
                    else:
                        st.error(message)


def page_dashboard():
    """Main dashboard page with graph management."""
    check_session_expiry()
    
    # Apply dashboard-specific background with higher specificity
    st.markdown("""
    <style>
        /* Dashboard background colors */
        body { background-color: #87CEEB !important; }
        .main { background-color: #87CEEB !important; }
        [data-testid="stAppViewContainer"] { background-color: #87CEEB !important; }
        [data-testid="stSidebar"] { background-color: #87CEEB !important; }
        .card { background-color: #A4D4F0 !important; }
        .stTabs { background-color: #A4D4F0 !important; }
        div[data-testid="stVerticalBlock"] { background-color: #87CEEB !important; }
        
        /* Dashboard container styling - pale light lavender */
        .stContainer, [data-testid="stContainer"] {
            background-color: #F0E6FF !important;
            border-radius: 8px !important;
        }
        
        /* More specific targeting for containers with borders */
        div[data-testid="stVerticalBlock"] .stContainer {
            background-color: #F0E6FF !important;
        }
        
        /* Target any container-like elements in the dashboard */
        [data-testid="stAppViewContainer"] .stContainer {
            background-color: #F0E6FF !important;
        }
        
        /* Also target the inner content areas */
        [data-testid="stAppViewContainer"] .stContainer > div {
            background-color: #F0E6FF !important;
        }
        
        /* Force override any default container backgrounds */
        [data-testid="stAppViewContainer"] [data-testid*="container"] {
            background-color: #F0E6FF !important;
        }
        
        /* Target elements that might have the blue background */
        [data-testid="stAppViewContainer"] div[style*="background-color"] {
            background-color: #F0E6FF !important;
        }
        
        /* Dashboard button styling - light coral */
        [data-testid="stAppViewContainer"] .stButton > button {
            background: #F08080 !important; /* Light coral */
            color: white !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 12px 24px !important;
            font-weight: 600 !important;
            font-size: 1em !important;
            transition: all 0.3s ease !important;
            width: 100% !important;
        }
        
        [data-testid="stAppViewContainer"] .stButton > button:hover {
            background: #FF7F7F !important; /* Slightly lighter coral on hover */
            transform: translateY(-2px) !important;
            box-shadow: 0 4px 12px rgba(240, 128, 128, 0.4) !important;
        }
        
        /* Account page specific styling - deep brown background ONLY for empty white spaces */
        /* Target the main container background only */
        [data-testid="stAppViewContainer"]:has(.account-header) {
            background-color: #654321 !important; /* Deep brown for white background spaces */
        }
        
        /* Keep boxes, containers, and buttons with their original styling - DO NOT CHANGE */
        [data-testid="stAppViewContainer"]:has(.account-header) .stContainer,
        [data-testid="stAppViewContainer"]:has(.account-header) [data-testid*="stContainer"],
        [data-testid="stAppViewContainer"]:has(.account-header) .stForm,
        [data-testid="stAppViewContainer"]:has(.account-header) .stButton {
            /* Keep original styling - don't override */
        }
        
        /* Account page text colors - light cream for visibility on deep brown background */
        [data-testid="stAppViewContainer"]:has(.account-header) p {
            color: #F5DEB3 !important; /* Light cream for readability on brown */
        }
        
        [data-testid="stAppViewContainer"]:has(.account-header) span {
            color: #F5DEB3 !important; /* Light cream */
        }
        
        /* Account page subheaders - light cream */
        [data-testid="stAppViewContainer"]:has(.account-header) h2,
        [data-testid="stAppViewContainer"]:has(.account-header) h3,
        [data-testid="stAppViewContainer"]:has(.account-header) h4,
        [data-testid="stAppViewContainer"]:has(.account-header) h5,
        [data-testid="stAppViewContainer"]:has(.account-header) h6 {
            color: #F5DEB3 !important;
        }
        
        /* Account page dividers and other elements */
        [data-testid="stAppViewContainer"]:has(.account-header) .stCaption {
            color: #006400 !important;
        }
        
        /* Dashboard text colors - ultra specific selectors */
        div[data-testid="stAppViewContainer"] p:not([class*="header"]):not([class*="st-"]):not([data-testid]) { color: #8B4513 !important; }
        div[data-testid="stAppViewContainer"] span:not([class*="header"]):not([class*="st-"]) { color: #8B4513 !important; }
        div[data-testid="stAppViewContainer"] div:not([class*="header"]):not([class*="card"]):not([class*="st-"]):not([data-testid]) { color: #8B4513 !important; }
        
        /* Headings - maroon */
        div[data-testid="stAppViewContainer"] h1:not([class*="st-"]) { color: #800000 !important; }
        div[data-testid="stAppViewContainer"] h2:not([class*="st-"]) { color: #800000 !important; }
        div[data-testid="stAppViewContainer"] h3:not([class*="st-"]) { color: #800000 !important; }
        div[data-testid="stAppViewContainer"] h4:not([class*="st-"]) { color: #800000 !important; }
        div[data-testid="stAppViewContainer"] h5:not([class*="st-"]) { color: #800000 !important; }
        div[data-testid="stAppViewContainer"] h6:not([class*="st-"]) { color: #800000 !important; }
        
        /* Button text specifically */
        .stButton > button:not([disabled]) { color: #8B4513 !important; }
        .stButton > button:not([disabled]) * { color: #8B4513 !important; }
        
        /* Captions and small text */
        .stCaption, .stCaption * { color: #8B4513 !important; }
        
        /* Info messages */
        .stInfo, .stInfo * { color: #8B4513 !important; }
    </style>
    
    <script>
        // Apply text colors after page load to override Streamlit defaults
        setTimeout(function() {
            // Regular text - dark caramel
            const textElements = document.querySelectorAll('div[data-testid="stAppViewContainer"] p, div[data-testid="stAppViewContainer"] span, div[data-testid="stAppViewContainer"] div');
            textElements.forEach(el => {
                if (!el.closest('.header') && !el.closest('.st-') && !el.hasAttribute('data-testid') && !el.closest('button')) {
                    el.style.color = '#8B4513';
                }
            });
            
            // Headings - maroon
            const headingElements = document.querySelectorAll('div[data-testid="stAppViewContainer"] h1, div[data-testid="stAppViewContainer"] h2, div[data-testid="stAppViewContainer"] h3, div[data-testid="stAppViewContainer"] h4, div[data-testid="stAppViewContainer"] h5, div[data-testid="stAppViewContainer"] h6');
            headingElements.forEach(el => {
                if (!el.closest('.st-')) {
                    el.style.color = '#800000';
                }
            });
            
            // Button text
            const buttons = document.querySelectorAll('.stButton > button');
            buttons.forEach(btn => {
                if (!btn.disabled) {
                    btn.style.color = '#8B4513';
                }
            });
        }, 1000);
    </script>
    """, unsafe_allow_html=True)
    
    st.markdown(f"""
    <div class="header">
        <h1>📊 Welcome, {ss.username}!</h1>
        <p>Your Secure Graph Gallery</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("➕ New Graph", use_container_width=True, key="btn_new"):
            ss.current_page = "create_graph"
            st.rerun()
    
    with col2:
        if st.button("📋 Account", use_container_width=True, key="btn_account"):
            ss.current_page = "account"
            st.rerun()
    
    with col3:
        if st.button("🚪 Logout", use_container_width=True, key="btn_logout"):
            logout()
            st.rerun()
    
    st.divider()
    
    # Get user's graphs
    graphs = get_user_graphs(ss.user_id)
    
    if not graphs:
        st.info("📭 No graphs yet. Click 'New Graph' to create your first one!")
    else:
        st.subheader(f"Your Graphs ({len(graphs)})")
        
        # Display graphs in grid
        cols = st.columns(3)
        for idx, graph in enumerate(graphs):
            with cols[idx % 3]:
                with st.container(border=True):
                    st.write(f"📈 **{graph['graph_name']}**")
                    st.caption(f"Type: {graph['graph_type']}")
                    st.caption(f"Created: {graph['created_at'][:10]}")
                    
                    col_view, col_delete = st.columns(2)
                    with col_view:
                        if st.button("👁️ View", key=f"view_{graph['id']}", use_container_width=True):
                            ss.selected_graph_id = graph['id']
                            ss.current_page = "view_graph"
                            st.rerun()
                    
                    with col_delete:
                        if st.button("🗑️ Delete", key=f"delete_{graph['id']}", use_container_width=True):
                            if delete_graph(graph['id'], ss.user_id):
                                st.success("Graph deleted")
                                st.rerun()
                            else:
                                st.error("Failed to delete graph")


def page_create_graph():
    """Create new graph page."""
    check_session_expiry()
    
    st.markdown(f"""
    <div class="header">
        <h1>➕ Create New Graph</h1>
        <p>Choose a type and enter your data</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("← Back to Dashboard", key="back_to_dash"):
        ss.current_page = "dashboard"
        st.rerun()
    
    st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Graph metadata
        st.subheader("📋 Graph Information")
        graph_type = st.selectbox("Graph Type", [
            "Line Graph", "Scatter Plot", "Histogram",
            "Pie Chart", "Box-and-Whisker Plot"
        ])
        
        graph_name = st.text_input("Graph Name", placeholder="e.g., Sales 2024 Q1")
        title = st.text_input("Chart Title", placeholder="e.g., Monthly Sales Data")
        description = st.text_area("Description (optional)", placeholder="Describe your graph...")
    
    with col2:
        st.subheader("📊 Graph Data")
        
        if graph_type == "Line Graph":
            st.info("Enter X and Y values. Use comma-separated format.")
            x_label = st.text_input("X-Axis Label", value="X Values", key="x_label_line")
            y_label = st.text_input("Y-Axis Label", value="Y Values", key="y_label_line")
            x_values = st.text_area("X Values (comma-separated)", placeholder="1, 2, 3, 4, 5", key="x_values_line")
            y_values = st.text_area("Y Values (comma-separated)", placeholder="10, 15, 20, 18, 25", key="y_values_line")
        
        elif graph_type == "Scatter Plot":
            st.info("Enter X and Y values for scatter points.")
            x_label = st.text_input("X-Axis Label", value="X Values", key="x_label_scatter")
            y_label = st.text_input("Y-Axis Label", value="Y Values", key="y_label_scatter")
            x_values = st.text_area("X Values (comma-separated)", placeholder="1, 2, 3, 4, 5", key="x_values_scatter")
            y_values = st.text_area("Y Values (comma-separated)", placeholder="10, 15, 20, 18, 25", key="y_values_scatter")
        
        elif graph_type == "Histogram":
            st.info("Enter data values and number of bins.")
            x_label = st.text_input("X-Axis Label", value="Value", key="x_label_hist")
            y_label = st.text_input("Y-Axis Label", value="Frequency", key="y_label_hist")
            data = st.text_area("Data Values (comma-separated)", placeholder="10, 12, 15, 18, 20, 22, 25", key="data_hist")
            bins = st.slider("Number of Bins", min_value=2, max_value=100, value=10, key="bins_hist")
        
        elif graph_type == "Pie Chart":
            st.info("Enter labels and proportions.")
            labels = st.text_area("Labels (comma-separated)", placeholder="Slice A, Slice B, Slice C", key="labels_pie")
            proportions = st.text_area("Proportions (comma-separated)", placeholder="30, 50, 20", key="proportions_pie")
        
        elif graph_type == "Box-and-Whisker Plot":
            st.info("Enter data groups separated by |")
            labels = st.text_area("Group Labels (comma-separated)", placeholder="Group A, Group B, Group C", key="labels_box")
            data = st.text_area("Data Groups (use | to separate groups)", placeholder="1,2,3,4,5|6,7,8,9,10|11,12,13,14,15", key="data_box")
            y_label = st.text_input("Y-Axis Label", value="Value", key="y_label_box")
    
    st.divider()
    
    if st.button("✓ Create Graph", use_container_width=True, type="primary"):
        if not graph_name or not title:
            st.error("Please enter graph name and title")
        else:
            # Prepare parameters based on graph type
            params = {}
            
            if graph_type == "Line Graph":
                params = {'x_values': x_values, 'y_values': y_values, 'x_label': x_label, 'y_label': y_label}
            elif graph_type == "Scatter Plot":
                params = {'x_values': x_values, 'y_values': y_values, 'x_label': x_label, 'y_label': y_label}
            elif graph_type == "Histogram":
                params = {'data': data, 'x_label': x_label, 'y_label': y_label, 'bins': bins}
            elif graph_type == "Pie Chart":
                params = {'labels': labels, 'proportions': proportions}
            elif graph_type == "Box-and-Whisker Plot":
                params = {'labels': labels, 'data': data, 'y_label': y_label}
            
            success, message = create_and_save_graph(graph_type, graph_name, title, description or "", params)
            if success:
                st.success(message)
                st.balloons()
                #st.session_state.pop('graph_type', None)
                import time
                time.sleep(1)
                ss.current_page = "dashboard"
                st.rerun()
            else:
                st.error(message)


def page_view_graph():
    """View saved graph page."""
    check_session_expiry()
    
    if not ss.selected_graph_id:
        st.error("No graph selected")
        if st.button("← Back to Dashboard"):
            ss.current_page = "dashboard"
            st.rerun()
        return
    
    graph = get_graph(ss.selected_graph_id, ss.user_id)
    if not graph:
        st.error("Graph not found or you don't have permission to view it")
        if st.button("← Back to Dashboard"):
            ss.current_page = "dashboard"
            st.rerun()
        return
    
    st.markdown(f"""
    <div class="header">
        <h1>👁️ {graph['graph_name']}</h1>
        <p>{graph.get('description', 'No description')}</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("← Back to Dashboard"):
        ss.current_page = "dashboard"
        ss.selected_graph_id = None
        st.rerun()
    
    st.divider()
    
    # Decrypt and display graph
    try:
        decrypted_json = decrypt_data(graph['graph_data'])
        success, fig = deserialize_graph(decrypted_json)
        
        if success and fig:
            st.plotly_chart(fig, use_container_width=True)
            
            # Graph info
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Type", graph['graph_type'])
            with col2:
                st.metric("Created", graph['created_at'][:10])
            with col3:
                st.metric("Last Updated", graph['updated_at'][:10])
            
            st.divider()
            st.subheader("Parameters")
            try:
                params = json.loads(graph['parameters'])
                st.json(params)
            except:
                st.write("No parameters saved")
        else:
            st.error("Failed to load graph")
    
    except Exception as e:
        logger.error(f"Graph display error: {e}")
        st.error(f"Error displaying graph: {str(e)[:100]}")


def page_settings():
    """User settings page."""
    check_session_expiry()
    
    st.markdown(f"""
    <div class="header">
        <h1>⚙️ Settings</h1>
        <p>Manage your account preferences</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("← Back to Dashboard"):
        ss.current_page = "dashboard"
        st.rerun()
    
    st.divider()
    
    tab1, tab2 = st.tabs(["🔐 Security", "🔑 API Keys"])
    
    with tab1:
        st.subheader("2FA / MFA Settings")
        
        if ss.mfa_enabled:
            mfa_type_display = "Email" if ss.get('mfa_type') == 'email' else "Authenticator App (TOTP)"
            st.success(f"✓ Multi-Factor Authentication is enabled ({mfa_type_display})")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Disable MFA", key="disable_mfa"):
                    update_user_mfa(ss.user_id, None, False)
                    ss.mfa_enabled = False
                    ss.mfa_type = None
                    st.success("MFA disabled")
                    st.rerun()
            with col2:
                if st.button("Change MFA Method", key="change_mfa"):
                    ss.current_page = "setup_mfa"
                    st.rerun()
        else:
            st.warning("⚠️ Multi-Factor Authentication is not enabled")
            st.info("Enable MFA for enhanced security.")
            if st.button("Enable MFA", key="enable_mfa"):
                ss.current_page = "setup_mfa"
                st.rerun()
    
    with tab2:
        st.info("API key management coming soon!")


def page_account():
    """Account management page."""
    check_session_expiry()
    
    st.markdown(f"""
    <div class="header account-header">
        <h1>👤 Account Information</h1>
        <p>View and manage your account</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("← Back to Dashboard"):
        ss.current_page = "dashboard"
        st.rerun()
    
    st.divider()
    
    user = get_user_by_id(ss.user_id)
    if user:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Account Details")
            st.write(f"**Username:** {user['username']}")
            st.write(f"**Email:** {user['email']}")
            st.write(f"**Account Created:** {user['created_at'][:10]}")
            st.write(f"**Last Login:** {user.get('last_login', 'Never')}")
        
        with col2:
            st.subheader("Security")
            st.write(f"**MFA Status:** {'Enabled ✓' if user['mfa_enabled'] else 'Disabled ⚠️'}")
            st.write(f"**Password Changed:** {user['password_changed_at'][:10]}")
        
        st.divider()
        
        st.subheader("Change Password")
        with st.form("change_password_form"):
            old_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            
            if st.form_submit_button("✓ Change Password", use_container_width=True):
                if not all([old_password, new_password, confirm_password]):
                    st.error("Please fill all fields")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                elif not verify_password(old_password, user['password_hash']):
                    st.error("Current password is incorrect")
                else:
                    is_valid, error = validate_password_strength(new_password)
                    if not is_valid:
                        st.error(f"Weak password: {error}")
                    else:
                        new_hash = hash_password(new_password)
                        if update_password(ss.user_id, new_hash):
                            st.success("Password changed successfully")
                            log_security_event("password_changed", ss.username, "User changed password")
                        else:
                            st.error("Failed to change password")


def page_setup_mfa():
    """MFA setup page."""
    check_session_expiry()
    
    st.markdown(f"""
    <div class="header">
        <h1>🔐 Setup Multi-Factor Authentication</h1>
        <p>Secure your account</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("← Back to Dashboard"):
        ss.current_page = "dashboard"
        ss.mfa_secret_temp = None
        st.rerun()
    
    st.divider()
    
    setup_mfa()


# ============================================================================
# MAIN APP LOGIC
# ============================================================================

def main():
    """Main application logic."""
    
    # Route to appropriate page
    if not ss.authenticated:
        page_login()
    elif ss.current_page == "dashboard":
        page_dashboard()
    elif ss.current_page == "create_graph":
        page_create_graph()
    elif ss.current_page == "view_graph":
        page_view_graph()
    elif ss.current_page == "account":
        page_account()
    elif ss.current_page == "setup_mfa":
        page_setup_mfa()
    else:
        page_dashboard()


if __name__ == "__main__":
    main()
