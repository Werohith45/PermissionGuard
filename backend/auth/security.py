import hashlib
import hmac
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from backend.utils.config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRATION_HOURS
from backend.database.schema import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def hash_password(password: str) -> str:
    """Hash password using PBKDF2 with SHA-256 and constant salt for reliable cross-platform demo"""
    salt = b"permissionguard_secure_salt_2026"
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return pwd_hash.hex()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    expected_hash = hash_password(plain_password)
    return hmac.compare_digest(expected_hash, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.*, r.name as role_name, d.name as department_name 
            FROM users u
            JOIN roles r ON u.role_id = r.id
            JOIN departments d ON u.department_id = d.id
            WHERE u.id = ? AND u.status = 'ACTIVE'
        """, (user_id,))
        user = cursor.fetchone()
        if user is None:
            raise credentials_exception
        return user

def require_roles(*allowed_roles):
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user["role_name"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted for role '{current_user['role_name']}'"
            )
        return current_user
    return role_checker
