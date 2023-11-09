from sqlmodel import Field, SQLModel

from app.db.tables.base_class import StatusEnum, TimestampModel, UUIDModel


class AuthUserBase(SQLModel):
    name: str = Field(nullable=False)
    phone: str = Field(nullable=False)
    address: str = Field(nullable=False)
    role: str = Field(nullable=False)
    email: str = Field(nullable=False,unique=True)
    password: str = Field(nullable=False)


class AuthUser(AuthUserBase, UUIDModel, TimestampModel, table=True):
    status: StatusEnum = Field(default=StatusEnum.inactive)

    __tablename__ = "auth_user"