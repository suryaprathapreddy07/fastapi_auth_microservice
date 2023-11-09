from fastapi import APIRouter

# from api.routes.transactions import router as transactions_router
from app.api.routes.transactions import router as transactions_router
from app.api.routes.auth_user import router as auth_user_router


router = APIRouter()

# router.include_router(transactions_router, prefix="/transactions")
router.include_router(auth_user_router, prefix="/auth")