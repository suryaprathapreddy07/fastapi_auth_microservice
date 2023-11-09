from uuid import UUID

from app.db.tables.auth_user import AuthUserBase


class AuthUserCreate(AuthUserBase):
    ...


class AuthUserRead(AuthUserBase):
    id: UUID


class AuthUserPatch(AuthUserBase):
    ...

