"""
Security utilities for Sentinel.

Handles password hashing, JWT token generation and verification,
and other security-related functions.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status

from app.config import settings

# ================================================================
# Password Hashing
# ================================================================

# Password hashing context
# Using bcrypt for simplicity and compatibility
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.

    Args:
        plain_password: The password in plain text
        hashed_password: The hashed password from the database

    Returns:
        bool: True if the password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: The password to hash

    Returns:
        str: The hashed password
    """
    return pwd_context.hash(password)


# ================================================================
# JWT Token Management
# ================================================================

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.

    Args:
        data: The payload data to encode in the token
        expires_delta: Optional custom expiration time

    Returns:
        str: The encoded JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "type": "access",
        "iat": datetime.utcnow(),
    })
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """
    Create a JWT refresh token with longer expiry.

    Args:
        data: The payload data to encode in the token

    Returns:
        str: The encoded JWT refresh token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "iat": datetime.utcnow(),
    })
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and verify a JWT token.

    Args:
        token: The JWT token to decode

    Returns:
        Dict[str, Any]: The decoded payload

    Raises:
        HTTPException: If the token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify a JWT token without raising an exception.

    Args:
        token: The JWT token to verify

    Returns:
        Optional[Dict[str, Any]]: The payload if valid, None otherwise
    """
    try:
        return decode_token(token)
    except HTTPException:
        return None


def verify_token_type(payload: Dict[str, Any], expected_type: str) -> bool:
    """
    Verify that the token has the expected type.

    Args:
        payload: The decoded JWT payload
        expected_type: The expected token type ('access', 'refresh', 'password_reset', 'email_verification')

    Returns:
        bool: True if the token type matches, False otherwise
    """
    return payload.get("type") == expected_type


def get_token_expires_in() -> int:
    """
    Get access token expiry in seconds.

    Returns:
        int: Token expiry in seconds
    """
    return settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


def create_tokens(user_id: str, email: str) -> Dict[str, Any]:
    """
    Create both access and refresh tokens for a user.

    Args:
        user_id: The user's ID (UUID as string)
        email: The user's email

    Returns:
        Dict[str, Any]: Dictionary with access_token and refresh_token
    """
    token_data = {"sub": user_id, "email": email}

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": get_token_expires_in(),
    }


# ================================================================
# Password Reset Token
# ================================================================

def create_password_reset_token(user_id: str) -> str:
    """
    Create a password reset token.

    Args:
        user_id: The user's ID

    Returns:
        str: The encoded token
    """
    data = {"sub": user_id, "type": "password_reset"}
    expire = datetime.utcnow() + timedelta(hours=24)
    data.update({"exp": expire})
    return jwt.encode(
        data,
        settings.JWT_SECRET.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM
    )


def verify_password_reset_token(token: str) -> Optional[str]:
    """
    Verify a password reset token and return the user ID.

    Args:
        token: The token to verify

    Returns:
        Optional[str]: The user ID if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM]
        )
        if payload.get("type") != "password_reset":
            return None
        return payload.get("sub")
    except JWTError:
        return None


# ================================================================
# Email Verification Token
# ================================================================

def create_email_verification_token(email: str) -> str:
    """
    Create an email verification token.

    Args:
        email: The email to verify

    Returns:
        str: The encoded token
    """
    data = {"email": email, "type": "email_verification"}
    expire = datetime.utcnow() + timedelta(days=7)
    data.update({"exp": expire})
    return jwt.encode(
        data,
        settings.JWT_SECRET.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM
    )


def verify_email_verification_token(token: str) -> Optional[str]:
    """
    Verify an email verification token and return the email.

    Args:
        token: The token to verify

    Returns:
        Optional[str]: The email if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM]
        )
        if payload.get("type") != "email_verification":
            return None
        return payload.get("email")
    except JWTError:
        return None