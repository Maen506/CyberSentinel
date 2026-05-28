"""
Enhanced Environment Configuration Validator
Production-ready version
"""

import os
import sys
import json
import socket
from pathlib import Path
from dotenv import load_dotenv


def str_to_bool(value):
    """Convert string to boolean safely"""
    return str(value).lower() in ['true', '1', 'yes']


class EnvironmentValidator:
    def __init__(self):
        self.env_file = Path('.env')
        self.errors = []
        self.warnings = []
        self.success = []

    # ========================
    # LOAD ENV
    # ========================
    def load_env(self):
        if not self.env_file.exists():
            self.errors.append("❌ .env file not found. Run: cp .env.example .env")
            return False

        load_dotenv(self.env_file)
        self.success.append("✓ .env file loaded")
        return True

    # ========================
    # DATABASE
    # ========================
    def validate_database(self):
        print("\n📊 Validating Database Configuration...")

        required = ['DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME']

        for var in required:
            value = os.getenv(var)
            if not value:
                self.errors.append(f"❌ Missing: {var}")
            else:
                self.success.append(f"✓ {var}: {value if var != 'DB_PASSWORD' else '***'}")

        try:
            import mysql.connector

            conn = mysql.connector.connect(
                host=os.getenv('DB_HOST'),
                port=int(os.getenv('DB_PORT', 3306)),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD'),
                database=os.getenv('DB_NAME')
            )

            self.success.append("✓ Database connection successful")
            conn.close()

        except Exception as e:
            self.errors.append(f"❌ Database connection failed: {str(e)}")

    # ========================
    # VIRUSTOTAL
    # ========================
    def validate_virustotal(self):
        print("\n🔍 Validating VirusTotal Configuration...")

        api_key = os.getenv('VIRUSTOTAL_API_KEY')

        if not api_key:
            self.errors.append("❌ Missing: VIRUSTOTAL_API_KEY")
            return

        if api_key == 'your_virustotal_api_key_here':
            self.errors.append("❌ VIRUSTOTAL_API_KEY not configured")
            return

        self.success.append("✓ VIRUSTOTAL_API_KEY configured")

        try:
            import requests

            response = requests.get(
                'https://www.virustotal.com/api/v3/domains/google.com',
                headers={'x-apikey': api_key},
                timeout=(3, 5)
            )

            if response.status_code == 200:
                self.success.append("✓ VirusTotal API key is valid")
            elif response.status_code == 401:
                self.errors.append("❌ Invalid VirusTotal API key")
            else:
                self.warnings.append(f"⚠️ API returned {response.status_code}")

        except Exception as e:
            self.warnings.append(f"⚠️ Could not test API: {str(e)}")

    # ========================
    # PORT CHECK (IMPROVED)
    # ========================
    def is_port_available(self, port):
        """Check if port is free by binding"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('127.0.0.1', port))
            sock.close()
            return True
        except:
            return False

    # ========================
    # FLASK
    # ========================
    def validate_flask(self):
        print("\n🌐 Validating Flask Configuration...")

        required = ['FLASK_PORT', 'FLASK_ENV', 'SECRET_KEY']

        for var in required:
            value = os.getenv(var)
            if not value:
                self.errors.append(f"❌ Missing: {var}")
            else:
                display = value if var != 'SECRET_KEY' else '***'
                self.success.append(f"✓ {var}: {display}")

        port = int(os.getenv('FLASK_PORT', 5000))

        if self.is_port_available(port):
            self.success.append(f"✓ Flask port {port} is available")
        else:
            self.warnings.append(f"⚠️ Port {port} is in use")

        # Security check
        if len(os.getenv('SECRET_KEY', '')) < 16:
            self.warnings.append("⚠️ SECRET_KEY is too short")

    # ========================
    # HONEYPOTS
    # ========================
    def validate_honeypots(self):
        print("\n🍯 Validating Honeypots...")

        ssh_port = int(os.getenv('SSH_PORT', 2222))
        http_port = int(os.getenv('HTTP_PORT', 8080))

        for port, name in [(ssh_port, 'SSH'), (http_port, 'HTTP')]:
            if self.is_port_available(port):
                self.success.append(f"✓ {name} port {port} available")
            else:
                self.warnings.append(f"⚠️ {name} port {port} in use")

    # ========================
    # ML
    # ========================
    def validate_ml(self):
        print("\n🤖 Validating ML Configuration...")

        ml_enabled = str_to_bool(os.getenv('ML_ENABLED', 'True'))

        if not ml_enabled:
            self.warnings.append("⚠️ ML disabled")
            return

        self.success.append("✓ ML enabled")

        model_path = Path(os.getenv('ML_MODEL_PATH', 'ml/models'))

        if not model_path.exists():
            self.errors.append(f"❌ Model path not found: {model_path}")
            return

        models = list(model_path.glob('*.pkl'))

        if not models:
            self.errors.append("❌ No ML models found")
        else:
            self.success.append(f"✓ Found {len(models)} models")

    # ========================
    # MITRE
    # ========================
    def validate_mitre(self):
        print("\n🎯 Validating MITRE...")

        if str_to_bool(os.getenv('MITRE_ENABLED', 'True')):
            self.success.append("✓ MITRE enabled")
        else:
            self.warnings.append("⚠️ MITRE disabled")

    # ========================
    # LOGGING
    # ========================
    def validate_logging(self):
        print("\n📝 Validating Logging...")

        log_file = os.getenv('LOG_FILE', 'logs/honeytrack.log')
        log_dir = Path(log_file).parent

        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_file, 'a'):
                pass

            self.success.append(f"✓ Logging ready: {log_file}")

        except Exception as e:
            self.errors.append(f"❌ Logging failed: {e}")

    # ========================
    # EXPORT REPORT
    # ========================
    def export_report(self):
        report = {
            "success": self.success,
            "warnings": self.warnings,
            "errors": self.errors
        }

        with open("env_report.json", "w") as f:
            json.dump(report, f, indent=4)

    # ========================
    # REPORT
    # ========================
    def print_report(self):
        print("\n" + "=" * 60)
        print("VALIDATION REPORT")
        print("=" * 60)

        for section, data in [
            ("SUCCESS", self.success),
            ("WARNINGS", self.warnings),
            ("ERRORS", self.errors)
        ]:
            if data:
                print(f"\n{section}:")
                for msg in data:
                    print(f"  {msg}")

        print("\nSummary:")
        print(f"  Success: {len(self.success)}")
        print(f"  Warnings: {len(self.warnings)}")
        print(f"  Errors: {len(self.errors)}")

        print("=" * 60)

        self.export_report()

        return len(self.errors) == 0

    # ========================
    # RUN ALL
    # ========================
    def validate_all(self):
        if not self.load_env():
            return False

        self.validate_database()
        self.validate_virustotal()
        self.validate_flask()
        self.validate_honeypots()
        self.validate_ml()
        self.validate_mitre()
        self.validate_logging()

        return self.print_report()


def main():
    validator = EnvironmentValidator()
    success = validator.validate_all()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
