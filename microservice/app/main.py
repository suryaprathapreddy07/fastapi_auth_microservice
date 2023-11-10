from fastapi import FastAPI, status,Depends
from fastapi.openapi.models import Tag
from typing import Annotated

from app.api.router import router
from app.core.config import settings
from app.db.sessions import create_tables

from fastapi.security import OAuth2PasswordBearer


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
custom_tags = [
    Tag(name="Authentication", description="Operations related to Authentication"),
    
]



app = FastAPI(
    title=settings.title,
    version=settings.version,
    description=settings.description,
    openapi_prefix=settings.openapi_prefix,
    docs_url=settings.docs_url,
    openapi_url=settings.openapi_url,
    openapi_tags=custom_tags
)



app.include_router(router, prefix=settings.api_prefix)


@app.get("/")
async def root():
    return {"Say": "Hello!"}


@app.get("/init_tables", status_code=status.HTTP_200_OK, name="init_tables")
async def init_tables():
    create_tables()

