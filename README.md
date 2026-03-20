# 📊 ChartVault - Secure Graph Generator

A **production-grade, enterprise-secure data visualization platform** built with Streamlit, featuring user authentication, encryption, and comprehensive security measures.

---

## 🌟 Key Features

### 🔐 **Security-First Design**
- **AES-256-GCM Encryption** for stored graph data
- **Bcrypt password hashing** with 12 salt rounds
- **Time-based One-Time Password (TOTP) MFA** support
- **SQL injection prevention** via parameterized queries
- **XSS protection** and input sanitization
- **Session management** with automatic timeout
- **Account lockout** after failed login attempts
- **Comprehensive audit logging** for forensics

### 📈 **Graph Types**
1. **Line Graphs** - Trend visualization with markers and lines
2. **Scatter Plots** - Distribution and correlation analysis
3. **Histograms** - Frequency distribution with customizable bins
4. **Pie Charts** - Proportional representation with percentages
5. **Box-and-Whisker Plots** - Statistical distribution analysis

### 👥 **User Management**
- **Secure registration** with password strength validation
- **Multi-factor authentication (MFA)** with TOTP
- **Session management** with 30-minute automatic timeout
- **Password policy enforcement** (12+ chars, mixed case, numbers, special chars)
- **Account lockout protection** (5 failed attempts = 15min lockout)

### 💾 **Data Management**
- **Graph storage** per user with encryption
- **Graph metadata** (title, description, creation date)
- **Parameter backup** for reproducibility
- **Soft delete** for audit trail preservation

### 🎨 **Professional UI/UX**
- **Modern color scheme** with consistent branding
- **Responsive design** for all screen sizes
- **Intuitive navigation** with clear workflows
- **Real-time feedback** and validation messages

---

## 🏗️ Architecture

### **Tech Stack**
- **Frontend**: Streamlit (Python web framework)
- **Backend**: Python with SQLite
- **Encryption**: cryptography library (Fernet)
- **Authentication**: bcrypt + pyotp (TOTP)
- **Visualization**: Plotly

### **Project Structure**
```
├── streamlit_app.py       # Main application
├── config.py              # Configuration constants
├── security.py            # Authentication & encryption
├── database.py            # Database operations
├── validators.py          # Input validation
├── graphs.py              # Graph generation
└── requirements.txt       # Python dependencies
```

---

## 🚀 Installation & Setup

### **Prerequisites**
- Python 3.8+
- pip

### **Quick Start**
```bash
# 1. Clone and navigate
git clone <repo-url>
cd cyber_code_comp-app

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run application
streamlit run streamlit_app.py
```

The app will open at `http://localhost:8501`

---

## 📖 Quick Guide

### **Register**
1. Click "Register" tab
2. Create username, email, strong password
3. Account is ready

### **Create Graph**
1. Click "New Graph"
2. Select graph type
3. Enter data and labels
4. Click "Create Graph"

### **Enable Security (2FA)**
1. Go to Settings → Security
2. Click "Enable MFA"
3. Scan QR code with authenticator app
4. Verify code

---

## 🔒 Security Highlights

- ✅ **AES-256 encryption** for graphs at rest
- ✅ **Bcrypt password hashing** (12 rounds)
- ✅ **TOTP MFA** support
- ✅ **SQL injection prevention**
- ✅ **Input validation** and sanitization
- ✅ **Session timeout** (30 minutes)
- ✅ **Account lockout** protection
- ✅ **Audit logging** for forensics
- ✅ **OWASP Top 10** mitigation

---

## 📊 Supported Graphs

| Type | Use Case | Parameters |
|------|----------|-----------|
| **Line Graph** | Trends over time | X/Y values, labels |
| **Scatter Plot** | Correlations | X/Y values, labels |
| **Histogram** | Distributions | Data, bins (2-100) |
| **Pie Chart** | Proportions | Labels, proportions |
| **Box-Whisker** | Statistical range | Groups, data |

---

## 🐛 Troubleshooting

### App won't start
```bash
pip install -r requirements.txt
streamlit run streamlit_app.py --logger.level=debug
```

### Can't log in
- Check username/password
- Account may be locked (15min timeout after 5 failures)
- Clear browser cookies

### MFA issues
- Ensure device time is synced
- Try different authenticator app
- Manually enter code instead of scanning

---

## 📝 License & Support

For security issues, contact: security@chartvault.com

---

**ChartVault v1.0** - Secure data visualization made simple. 📊🔐
