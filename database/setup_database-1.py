"""
HoneyTrack — setup_db.py
Run ONCE before first launch to create MySQL database and all 9 tables.

USAGE:
    python setup_db.py --configure
"""
import sys, os, getpass
from pathlib import Path
from typing import Optional
# Load .env
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

sys.path.insert(0, str(Path(__file__).parent))


def setup(root_password: str):
    import mysql.connector

    print("\n[1/3] Connecting to MySQL as root...")
    try:
        conn = mysql.connector.connect(
            host     = os.getenv("DB_HOST","localhost"),
            port     = int(os.getenv("DB_PORT","3306")),
            user     = "root",
            password = root_password,
        )
    except Exception as e:
        print(f"  ✗ Cannot connect to MySQL: {e}")
        print("  Make sure MySQL is running and root password is correct.")
        sys.exit(1)

    cur = conn.cursor()

    db_name   = os.getenv("DB_NAME","honeypot_db")
    db_user   = os.getenv("DB_USER","honeypot_user")
    db_pass   = os.getenv("DB_PASSWORD", os.getenv("DB_PASS","HoneyTrack@2026!"))

    cmds = [
        f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
        f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}'",
        f"CREATE USER IF NOT EXISTS '{db_user}'@'%'         IDENTIFIED BY '{db_pass}'",
        f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'",
        f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'%'",
        "FLUSH PRIVILEGES",
    ]

    for cmd in cmds:
        try:
            cur.execute(cmd)
            short = cmd[:70]
            print(f"  ✔ {short}")
        except Exception as ex:
            if "already exists" not in str(ex).lower():
                print(f"  ⚠ {ex}")

    conn.commit()
    conn.close()
    print("\n[2/3] Database and user created.")

    # Set env vars for db_manager
    os.environ["DB_USER"]     = db_user
    os.environ["DB_PASSWORD"] = db_pass
    os.environ["DB_PASS"]     = db_pass
    os.environ["DB_NAME"]     = db_name

    print("\n[3/3] Creating all 9 tables...")
    from database.db_manager import initialize_database
    initialize_database()

    print("\n" + "═"*55)
    print("  ✔  Setup Complete!")
    print(f"  Database : {db_name}")
    print(f"  User     : {db_user}")
    print(f"  Password : {db_pass}")
    print("═"*55)
    print("\n  Next step: python main.py\n")


def test_connection():
    """Test DB connection without root"""
    import mysql.connector
    try:
        conn = mysql.connector.connect(
            host     = os.getenv("DB_HOST","localhost"),
            port     = int(os.getenv("DB_PORT","3306")),
            user     = os.getenv("DB_USER","honeypot_user"),
            password = os.getenv("DB_PASSWORD",os.getenv("DB_PASS","HoneyTrack@2026!")),
            database = os.getenv("DB_NAME","honeypot_db"),
        )
        conn.close()
        print("  ✔ Connection test passed!")
        return True
    except Exception as e:
        print(f"  ✗ Connection test failed: {e}")
        return False


if __name__ == "__main__":
    if "--configure" not in sys.argv and "--test" not in sys.argv:
        print("HoneyTrack Database Setup")
        print("─"*40)
        print("Usage:")
        print("  python setup_db.py --configure    Setup database (run once)")
        print("  python setup_db.py --test         Test connection")
        sys.exit(0)

    if "--test" in sys.argv:
        test_connection()
        sys.exit(0)

    print("╔══════════════════════════════════════════╗")
    print("║    HoneyTrack — Database Setup           ║")
    print("╚══════════════════════════════════════════╝")
    print("\nThis will create:")
    print(f"  Database: {os.getenv('DB_NAME','honeypot_db')}")
    print(f"  User:     {os.getenv('DB_USER','honeypot_user')}")
    print(f"  Tables:   9 tables\n")

    try:
        root_pw = getpass.getpass("Enter MySQL ROOT password: ")
        setup(root_pw)
    except KeyboardInterrupt:
        print("\nCancelled.")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)