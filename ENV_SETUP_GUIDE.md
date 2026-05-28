# HoneyTrack Environment Configuration Guide

Complete guide for setting up `.env` file with all API keys and configurations.

## Quick Start

```bash
# 1. Copy the example file
cp .env.example .env

# 2. Edit with your values
nano .env

# 3. Make sure it's not committed
echo ".env" >> .gitignore
```

## Required Configuration

### 1. Database Configuration

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=honeypot_user
DB_PASSWORD=your_secure_password_here
DB_NAME=honeypot_db
DB_CHARSET=utf8mb4
```

**Setup MySQL:**
```bash
# Create database
mysql -u root -p -e "CREATE DATABASE honeypot_db CHARACTER SET utf8mb4;"

# Create user
mysql -u root -p -e "CREATE USER 'honeypot_user'@'localhost' IDENTIFIED BY 'your_secure_password_here';"

# Grant privileges
mysql -u root -p -e "GRANT ALL PRIVILEGES ON honeypot_db.* TO 'honeypot_user'@'localhost';"
mysql -u root -p -e "FLUSH PRIVILEGES;"
```

### 2. VirusTotal API Configuration ⭐

**Get API Key:**
1. Visit: https://www.virustotal.com/gui/my-apikey
2. Sign up or log in to VirusTotal
3. Copy your API key
4. Add to `.env`:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
VIRUSTOTAL_API_URL=https://www.virustotal.com/api/v3
VIRUSTOTAL_TIMEOUT=10
VIRUSTOTAL_RATE_LIMIT=4
VIRUSTOTAL_ENABLED=True
```

**API Key Types:**
- **Free Tier**: 4 requests/minute
- **Premium**: Higher rate limits

**Usage Example:**
```python
from virustotal.vt_client import VirusTotalClient

vt = VirusTotalClient()
result = vt.check_ip('192.168.1.1')
print(result)
```

### 3. SSH Honeypot Configuration

```env
SSH_PORT=2222
SSH_HOST=0.0.0.0
SSH_BANNER=SSH-2.0-OpenSSH_7.4
SSH_KEY_FILE=ssh_key.pem
SSH_LOG_LEVEL=INFO
```

**Generate SSH Key:**
```bash
ssh-keygen -t rsa -b 2048 -f ssh_key.pem -N ""
```

### 4. HTTP Honeypot Configuration

```env
HTTP_PORT=8080
HTTP_HOST=0.0.0.0
HTTP_TIMEOUT=30
HTTP_MAX_CONNECTIONS=100
HTTP_LOG_LEVEL=INFO
```

### 5. Flask Web Application

```env
FLASK_APP=main.py
FLASK_ENV=production
FLASK_DEBUG=False
FLASK_PORT=5000
FLASK_HOST=0.0.0.0
SECRET_KEY=your_secret_key_here_change_this
```

**Generate Secret Key:**
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 6. Machine Learning Configuration

```env
ML_MODEL_PATH=ml/models
ML_DATA_PATH=ml/data
ML_BATCH_SIZE=32
ML_THRESHOLD_NORMAL=0.5
ML_THRESHOLD_ATTACK=0.7
ML_ENABLED=True
```

### 7. MITRE ATT&CK Configuration

```env
MITRE_ENABLED=True
MITRE_FRAMEWORK_VERSION=13.0
MITRE_MAPPING_ENABLED=True
```

### 8. Logging Configuration

```env
LOG_LEVEL=INFO
LOG_FILE=logs/honeytrack.log
LOG_MAX_SIZE=10485760
LOG_BACKUP_COUNT=5
LOG_FORMAT=%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

### 9. Alert Configuration

```env
ALERT_ENABLED=True
ALERT_HIGH_SEVERITY_THRESHOLD=0.8
ALERT_MEDIUM_SEVERITY_THRESHOLD=0.6
ALERT_LOW_SEVERITY_THRESHOLD=0.4
```

## Optional Configuration

### Email Notifications

```env
NOTIFICATION_EMAIL_ENABLED=True
NOTIFICATION_EMAIL_FROM=honeytrack@example.com
NOTIFICATION_EMAIL_TO=admin@example.com
NOTIFICATION_SMTP_SERVER=smtp.gmail.com
NOTIFICATION_SMTP_PORT=587
NOTIFICATION_SMTP_USERNAME=your_email@gmail.com
NOTIFICATION_SMTP_PASSWORD=your_app_password_here
```

**Gmail Setup:**
1. Enable 2-factor authentication
2. Create app password: https://myaccount.google.com/apppasswords
3. Use app password in `NOTIFICATION_SMTP_PASSWORD`

### Slack Notifications

```env
NOTIFICATION_SLACK_ENABLED=True
NOTIFICATION_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
NOTIFICATION_SLACK_CHANNEL=#security-alerts
```

**Create Slack Webhook:**
1. Go to: https://api.slack.com/apps
2. Create new app
3. Enable Incoming Webhooks
4. Create new webhook for your channel
5. Copy webhook URL

### Geolocation API

```env
GEOLOCATION_ENABLED=True
GEOLOCATION_API_KEY=your_ip_api_key_here
GEOLOCATION_API_URL=http://ip-api.com/json
GEOLOCATION_TIMEOUT=5
```

**Get API Key:**
1. Visit: https://ip-api.com/
2. Sign up for free tier
3. Copy your API key

## Security Best Practices

### 1. Protect `.env` File

```bash
# Make it readable only by owner
chmod 600 .env

# Add to .gitignore
echo ".env" >> .gitignore
echo ".env.local" >> .gitignore
```

### 2. Use Strong Passwords

```bash
# Generate strong password
openssl rand -base64 32
```

### 3. Rotate API Keys Regularly

- VirusTotal: Monthly
- Email: Quarterly
- Database: Quarterly

### 4. Use Environment-Specific Files

```bash
.env              # Production
.env.development  # Development
.env.testing      # Testing
```

### 5. Never Commit Secrets

```bash
# Verify .env is in .gitignore
cat .gitignore | grep .env

# Check git status
git status
```

## Loading Environment Variables

### Python

```python
import os
from dotenv import load_dotenv

# Load from .env file
load_dotenv()

# Access variables
db_host = os.getenv('DB_HOST')
vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
```

### Using in Code

```python
import os

class Config:
    """Application configuration"""
    
    # Database
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_NAME = os.getenv('DB_NAME', 'honeypot_db')
    
    # VirusTotal
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    VIRUSTOTAL_ENABLED = os.getenv('VIRUSTOTAL_ENABLED', 'True') == 'True'
    
    # Flask
    FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
    SECRET_KEY = os.getenv('SECRET_KEY')
```

## Validation

### Check Configuration

```bash
# Verify all required variables are set
python3 << 'EOF'
import os
from dotenv import load_dotenv

load_dotenv()

required = [
    'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME',
    'VIRUSTOTAL_API_KEY',
    'SSH_PORT', 'HTTP_PORT', 'FLASK_PORT',
    'SECRET_KEY'
]

missing = []
for var in required:
    if not os.getenv(var):
        missing.append(var)

if missing:
    print(f"Missing variables: {', '.join(missing)}")
else:
    print("✓ All required variables are set")
EOF
```

## Troubleshooting

### Issue: "VIRUSTOTAL_API_KEY not found"

**Solution:**
1. Check `.env` file exists
2. Verify variable name is correct
3. Ensure no spaces around `=`
4. Reload environment: `source .env`

### Issue: "Database connection failed"

**Solution:**
1. Verify MySQL is running: `mysql -u root -p`
2. Check credentials in `.env`
3. Verify database exists: `mysql -u honeypot_user -p -e "USE honeypot_db;"`

### Issue: "VirusTotal API rate limit exceeded"

**Solution:**
1. Increase `VIRUSTOTAL_RATE_LIMIT` (if premium)
2. Reduce check frequency
3. Implement caching

### Issue: "Flask port already in use"

**Solution:**
1. Change `FLASK_PORT` in `.env`
2. Or kill existing process: `lsof -i :5000`

## Example .env File

```env
# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=honeypot_user
DB_PASSWORD=SecurePass123!@#
DB_NAME=honeypot_db

# SSH
SSH_PORT=2222
SSH_HOST=0.0.0.0

# HTTP
HTTP_PORT=8080
HTTP_HOST=0.0.0.0

# Flask
FLASK_PORT=5000
FLASK_ENV=production
SECRET_KEY=abc123def456ghi789jkl012mno345pqr678stu

# VirusTotal
VIRUSTOTAL_API_KEY=your_api_key_from_virustotal_com
VIRUSTOTAL_ENABLED=True

# ML
ML_ENABLED=True

# MITRE
MITRE_ENABLED=True

# Logging
LOG_LEVEL=INFO

# Alerts
ALERT_ENABLED=True
```

## References

- **VirusTotal API**: https://developers.virustotal.com/reference/
- **Python dotenv**: https://pypi.org/project/python-dotenv/
- **Environment Variables**: https://en.wikipedia.org/wiki/Environment_variable

---

**Last Updated**: April 2026
**Version**: 1.0.0
