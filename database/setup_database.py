"""
╔══════════════════════════════════════════════════════════════╗
║         HoneyTrack - MySQL Setup Script                     ║
║         Run this once to setup the database                 ║
╚══════════════════════════════════════════════════════════════╝

HOW TO USE:
  1. Install MySQL (see instructions below)
  2. Run: python setup_database.py
"""

import subprocess
import sys
import os

# ══════════════════════════════════════════════
# STEP 1 — Instructions (print and wait)
# ══════════════════════════════════════════════
INSTRUCTIONS = """
╔══════════════════════════════════════════════════════════════╗
║              MySQL Installation Guide                       ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  WINDOWS:                                                    ║
║  1. Download MySQL Installer:                                ║
║     https://dev.mysql.com/downloads/installer/              ║
║  2. Choose "MySQL Server" only                               ║
║  3. Set root password (remember it!)                         ║
║  4. Keep default port: 3306                                  ║
║                                                              ║
║  UBUNTU/LINUX:                                               ║
║  sudo apt update                                             ║
║  sudo apt install mysql-server -y                            ║
║  sudo mysql_secure_installation                              ║
║                                                              ║
║  After installation, come back and run:                      ║
║     python setup_database.py --configure                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

# ══════════════════════════════════════════════
# STEP 2 — Auto-configure MySQL
# ══════════════════════════════════════════════
SETUP_SQL = """
-- Create database
CREATE DATABASE IF NOT EXISTS honeypot_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- Create dedicated user (more secure than using root)
CREATE USER IF NOT EXISTS 'honeypot_user'@'localhost'
    IDENTIFIED BY 'HoneyTrack@2026!';

-- Grant permissions only on honeypot_db
GRANT ALL PRIVILEGES ON honeypot_db.* TO 'honeypot_user'@'localhost';

-- Allow remote connections (for external DB server)
CREATE USER IF NOT EXISTS 'honeypot_user'@'%'
    IDENTIFIED BY 'HoneyTrack@2026!';
GRANT ALL PRIVILEGES ON honeypot_db.* TO 'honeypot_user'@'%';

FLUSH PRIVILEGES;

-- Verify
SHOW DATABASES;
SELECT User, Host FROM mysql.user WHERE User='honeypot_user';
"""


def run_mysql_setup(root_password: str):
    """Run MySQL setup SQL as root"""
    print("\n[*] Configuring MySQL...")

    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password=root_password,
            port=3306
        )
        cursor = conn.cursor()

        statements = [s.strip() for s in SETUP_SQL.split(';') if s.strip()
                      and not s.strip().startswith('--')]

        for stmt in statements:
            try:
                cursor.execute(stmt)
                result = cursor.fetchall()
                if result:
                    for row in result:
                        print(f"   {row}")
            except Exception as e:
                if "already exists" not in str(e).lower():
                    print(f"   [!] {e}")

        conn.commit()
        conn.close()
        print("\n  ✔ Database 'honeypot_db' created")
        print("  ✔ User 'honeypot_user' created")
        print("  ✔ Permissions granted")

    except Exception as e:
        print(f"\n  [ERROR] {e}")
        print("  Make sure MySQL is running and root password is correct.")
        sys.exit(1)


def test_connection():
    """Test connection with honeypot_user"""
    print("\n[*] Testing connection with honeypot_user...")
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host="localhost",
            user="honeypot_user",
            password="HoneyTrack@2026!",
            database="honeypot_db",
            port=3306
        )
        conn.close()
        print("  ✔ Connection successful!")
        return True
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


def initialize_tables():
    """Create all honeypot tables"""
    print("\n[*] Creating database tables...")

    # Add parent dir to path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    # Set env vars for db_manager
    os.environ['DB_HOST']     = 'localhost'
    os.environ['DB_USER']     = 'honeypot_user'
    os.environ['DB_PASS']     = 'HoneyTrack@2026!'
    os.environ['DB_NAME']     = 'honeypot_db'
    os.environ['DB_PORT']     = '3306'

    from database.db_manager import initialize_database
    initialize_database()


def generate_env_file():
    """Write .env file with credentials"""
    env_content = """# HoneyTrack Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=honeypot_user
DB_PASS=HoneyTrack@2026!
DB_NAME=honeypot_db

# VirusTotal API Key
# Get free key at: https://www.virustotal.com/gui/join-us
VT_API_KEY=YOUR_VT_API_KEY_HERE

# Ports
SSH_PORT=2222
HTTP_PORT=8080
DASHBOARD_PORT=5000
"""
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    with open(env_path, 'w') as f:
        f.write(env_content)
    print(f"\n  ✔ .env file created: {env_path}")
    print("  ⚠  Remember to add your VirusTotal API key to .env")


def verify_setup():
    """Quick verification that everything is working"""
    print("\n[*] Verifying setup...")
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host="localhost",
            user="honeypot_user",
            password="HoneyTrack@2026!",
            database="honeypot_db"
        )
        cur = conn.cursor()
        cur.execute("SHOW TABLES")
        tables = [t[0] for t in cur.fetchall()]
        conn.close()

        print(f"\n  ✔ Found {len(tables)} tables:")
        for t in tables:
            print(f"     → {t}")

        return len(tables) == 9
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False


# ══════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════
if __name__ == '__main__':

    print(INSTRUCTIONS)

    if '--configure' not in sys.argv:
        print("Run with --configure flag when MySQL is installed:")
        print("  python setup_database.py --configure")
        sys.exit(0)

    print("╔══════════════════════════════════════════════════════════╗")
    print("║            HoneyTrack Database Setup                    ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    # Get root password
    import getpass
    root_pass = getpass.getpass("Enter MySQL root password: ")

    # Run setup
    run_mysql_setup(root_pass)
    test_connection()
    initialize_tables()
    generate_env_file()

    ok = verify_setup()

    print("\n" + "╔" + "═"*56 + "╗")
    if ok:
        print("║" + "  ✔  Setup Complete! All 9 tables ready.".center(56) + "║")
        print("╠" + "═"*56 + "╣")
        print("║  Next step:".ljust(57) + "║")
        print("║    cd dashboard && python app.py".ljust(57) + "║")
        print("║    Open: http://localhost:5000".ljust(57) + "║")
    else:
        print("║" + "  ✗  Setup incomplete. Check errors above.".center(56) + "║")
    print("╚" + "═"*56 + "╝\n")
