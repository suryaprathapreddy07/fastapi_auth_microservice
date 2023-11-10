
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
import jwt
from app.core.config import settings
from jwt import PyJWTError
from typing import Annotated

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.ALGORITHM])
        return payload
    except PyJWTError:
        raise credentials_exception