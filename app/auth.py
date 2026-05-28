# app/auth.py
import hashlib
import secrets
from datetime import datetime, timedelta
import jwt
from functools import wraps
from flask import request, jsonify, redirect

# ═══════════════════════════════════════════════
# التكوين
# ═══════════════════════════════════════════════
SECRET_KEY = os.environ.get('JWT_SECRET', secrets.token_hex(32))
TOKEN_EXPIRY_HOURS = 24

# مستخدم المشرف الافتراضي (تغييره في production)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'HoneyTrack2026!')

import os

def hash_password(password):
    """تشفير كلمة المرور"""
    return hashlib.sha256(password.encode()).hexdigest()

# كلمة المرور المشفرة
ADMIN_PASSWORD_HASH = hash_password(ADMIN_PASSWORD)

# ═══════════════════════════════════════════════
# JWT Token Management
# ═══════════════════════════════════════════════
def generate_token(username):
    """توليد JWT token"""
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS),
        'iat': datetime.utcnow(),
        'jti': secrets.token_hex(16)  # معرف فريد للـ token
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    """التحقق من صحة الـ token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ═══════════════════════════════════════════════
# Decorators للحماية
# ═══════════════════════════════════════════════
def login_required(f):
    """لحماية API routes - يرجع JSON إذا غير مصرح"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # فحص الـ token في الهيدر أو الكوكيز
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            token = request.cookies.get('auth_token')
        
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        # إضافة معلومات المستخدم للـ request
        request.user = payload
        return f(*args, **kwargs)
    
    return decorated

def login_page_required(f):
    """لحماية صفحات HTML - يوجه لصفحة تسجيل الدخول"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')
        
        if not token:
            return redirect('/login')
        
        payload = verify_token(token)
        if not payload:
            return redirect('/login')
        
        request.user = payload
        return f(*args, **kwargs)
    
    return decorated

def verify_login(username, password):
    """التحقق من بيانات الدخول"""
    if username == ADMIN_USERNAME and hash_password(password) == ADMIN_PASSWORD_HASH:
        return True
    return False