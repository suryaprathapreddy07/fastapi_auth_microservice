class EntityDoesNotExist(Exception):
    """Raised when entity was not found in database."""

# app.db.errors.py

from fastapi import HTTPException
from starlette import status

class EmailAlreadyExistsError(HTTPException):
    def __init__(self):
        detail = "Email already exists"
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
