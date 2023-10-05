from datetime import datetime, timedelta, timezone
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


def create_access_token(sub: str, refresh_token_expiration_datetime: datetime = None) -> str:
    token_expiration_datetime = datetime.now(
        timezone.utc) + timedelta(seconds=get_setting().TOKEN_EXPIRE_SECONDS)

    # If a refresh token expiration datetime is provided and it's earlier than the default expiration, use it instead.
    if refresh_token_expiration_datetime and refresh_token_expiration_datetime < token_expiration_datetime:
        token_expiration_datetime = refresh_token_expiration_datetime

    to_encode = {"sub": sub, "exp": token_expiration_datetime}
    encoded_jwt = jwt.encode(to_encode, get_setting(
    ).JWT_SECRET_KEY, get_setting().JWT_ALGORITHM)
    logger_access.info(f"Access token created, sub={sub}")
    return encoded_jwt


def create_refresh_token(sub: str, expiration_in_seconds: int = 0) -> str:
    if expiration_in_seconds is None:
        expiration_in_seconds = get_setting().TOKEN_EXPIRE_SECONDS
    token_expiration_datetime = datetime.now(
        timezone.utc) + timedelta(seconds=expiration_in_seconds)

    to_encode = {"sub": sub, "exp": token_expiration_datetime}
    encoded_jwt = jwt.encode(to_encode, get_setting(
    ).JWT_REFRESH_SECRET_KEY, get_setting().JWT_ALGORITHM)
    logger_access.info(f"Refresh token created, sub={sub}")
    return encoded_jwt, token_expiration_datetime


def refresh_access_token(refresh_token) -> str:
    payload = decode_jwt_token(
        refresh_token, get_setting().JWT_REFRESH_SECRET_KEY)
    return create_access_token(payload['sub'], datetime.fromtimestamp(payload['exp'], timezone.utc))
