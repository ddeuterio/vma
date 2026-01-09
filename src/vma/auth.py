from typing import Annotated
import os
from loguru import logger
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import Request, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from dotenv import load_dotenv
import secrets
import base64

import vma.api.models.v1 as mod_v1
from vma import connector as c
from vma import helper as h

load_dotenv()

MIN_LEN_SECRET_KEY = 32

_secret_key_access = os.getenv("SECRET_KEY_ACCESS")

if not _secret_key_access or len(_secret_key_access) < MIN_LEN_SECRET_KEY:
    raise ValueError(
        f"SECRET_KEY_ACCESS must be at least {MIN_LEN_SECRET_KEY} characters"
    )

_secret_key_refresh = os.getenv("SECRET_KEY_REFRESH")

if not _secret_key_refresh or len(_secret_key_refresh) < MIN_LEN_SECRET_KEY:
    raise ValueError(
        f"SECRET_KEY_REFRESH must be at least {MIN_LEN_SECRET_KEY} characters"
    )

_algorithm = os.getenv("TOKEN_ALG") or "HS256"
_expire_access_token = int(os.getenv("ACCESS_TOKEN_EXP_TIME") or "15")
_expire_refresh_token = int(os.getenv("REFRESH_TOKEN_EXP_TIME") or "2")


hasher = PasswordHash((Argon2Hasher(),))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_token(username: str, ttype: str, scope: dict, root: bool) -> str:
    expire, key = None, None
    if ttype == "access_token":
        expire = datetime.now(timezone.utc) + timedelta(minutes=_expire_access_token)
        key = _secret_key_access
    elif ttype == "refresh_token":
        expire = datetime.now(timezone.utc) + timedelta(days=_expire_refresh_token)
        key = _secret_key_refresh
    else:
        raise Exception("create_token; invalid ttype")

    data = {
        "sub": f"username:{username}",
        "exp": expire,
        "type": ttype,
        "scope": scope,
        "root": root,
    }
    return jwt.encode(payload=data, key=key, algorithm=_algorithm)


def validate_access_token(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> mod_v1.JwtData:
    cred_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    data = None
    try:
        payload = jwt.decode(jwt=token, key=_secret_key_access, algorithms=[_algorithm])
        if (
            not payload["sub"]
            or not payload["type"]
            or not payload["scope"]
            or payload["type"] != "access_token"
        ):
            raise cred_exception
        data = mod_v1.JwtData(
            username=payload["sub"].split(":")[-1],
            scope=payload["scope"],
            root=payload["root"],
        )
    except Exception as e:
        logger.error("Could not validate the token")
        logger.error(f"Error: {e}")
        raise cred_exception
    return data


async def is_authenticated(request: Request) -> mod_v1.JwtData | None:
    if not request.headers or ("Authorization" not in request.headers):
        return None
    auth_header = request.headers["Authorization"]
    token = auth_header.split(" ", 1)[1]
    try:
        return validate_access_token(token)
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            return None
        raise


def generate_api_token() -> str:
    """
    Generate a secure random API token.
    Format: vma_<base64_random>

    Returns:
        str: Token in format vma_xxxxx (48 characters total)
    """
    # Generate 32 random bytes
    random_bytes = secrets.token_bytes(32)

    # Base64 encode and remove padding
    token_suffix = base64.urlsafe_b64encode(random_bytes).decode("utf-8").rstrip("=")

    return f"vma_{token_suffix}"


async def validate_api_token(authorization: str = Header(None)) -> dict:
    """
    Validate API token and return user context with ALL user permissions.
    Token inherits all scopes from the user who created it.

    Args:
        token: The API token to validate (format: vma_xxxxx)

    Returns:
        dict: {
            "status": bool,
            "result": {
                "username": str (email),
                "teams": dict,  # ALL user's team scopes
                "root": bool,
                "token_type": "api_token",
                "token_id": int
            } or error message
        }
    """
    if not authorization.startswith("Bearer "):
        return {
            "status": False,
            "result": "Invalid authorization format. Use: Bearer <token>",
        }

    token = authorization.replace("Bearer ", "")

    if not token.startswith("vma_"):
        logger.error("Invalid token format, it does not start with vma_")
        return {"status": False, "result": h.errors["invalid_token_format"]}

    prefix = token[:12]
    result = await c.get_api_token_by_prefix(prefix)

    if not result["status"]:
        logger.error("Token was not identified, prefix does not exist in the database")
        return {"status": False, "result": h.errors["invalid_token_format"]}

    token_data = result["result"]

    if not hasher.verify(token, token_data["token_hash"]):
        logger.error("Hash verification failed")
        return {"status": False, "result": h.errors["invalid_token_format"]}

    if token_data["revoked"]:
        logger.debug("Token has been revoked")
        return {"status": False, "result": "Token has been revoked"}

    if token_data["expires_at"] and token_data["expires_at"] < datetime.now(
        timezone.utc
    ):
        logger.debug("Token has expired")
        return {"status": False, "result": "Token has expired"}

    await c.update_token_last_used(token_data["id"])

    user_result = await c.get_users(email=token_data["user_email"])
    if not user_result["status"] or not user_result["result"]:
        logger.debug("User not found")
        return {"status": False, "result": "User not found"}

    user = user_result["result"][0]

    logger.debug("API token is valid")

    return {
        "status": True,
        "result": {
            "username": user["email"],
            "teams": user.get("teams", {}),
            "root": user.get("is_root", False),
            "token_type": "api_token",
            "token_id": token_data["id"],
        },
    }
