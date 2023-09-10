from datetime import datetime, timedelta
import logging

import jwt
from passlib.context import CryptContext

from fastapi import HTTPException, status
from core.config import get_setting


logger_access = logging.getLogger('access')
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def decode_jwt_token(token: str, secret_key) -> dict:
    try:
        payload = jwt.decode(token, secret_key, algorithms=[get_setting().JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        msg = "Token has expired"
        logger_access.info(msg)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)
    except jwt.InvalidTokenError:
        msg = "Invalid token"
        logger_access.warning(msg)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)

def create_access_token(sub: str, expires_delta: timedelta = None) -> str:
    if expires_delta is not None:
        expires = datetime.utcnow() + expires_delta
    else:
        expires = datetime.utcnow() + timedelta(minutes=get_setting().ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"sub": sub, "exp": expires}
    encoded_jwt = jwt.encode(to_encode, get_setting().JWT_SECRET_KEY, get_setting().JWT_ALGORITHM)
    logger_access.info(f"Access token created, sub={sub}")
    return encoded_jwt

def create_refresh_token(sub: str, expires_delta: timedelta = None) -> str:
    if expires_delta is not None:
        expires = datetime.utcnow() + expires_delta
    else:
        expires = datetime.utcnow() + timedelta(minutes=get_setting().REFRESH_TOKEN_EXPIRE_MINUTES)

    to_encode = {"sub": sub, "exp": expires}
    encoded_jwt = jwt.encode(to_encode, get_setting().JWT_REFRESH_SECRET_KEY, get_setting().JWT_ALGORITHM)
    logger_access.info(f"Refresh token created, sub={sub}")
    return encoded_jwt

def refresh_access_token(refresh_token) -> str:
    sub = decode_jwt_token(refresh_token, get_setting().JWT_REFRESH_SECRET_KEY)['sub']
    return create_access_token(sub)
