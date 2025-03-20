from fastapi import FastAPI
from fastapi_async_sqlalchemy import SQLAlchemyMiddleware

from cactus_orchestrator.api.user import router as user_router
from cactus_orchestrator.settings import main_settings


app = FastAPI()


app.add_middleware(SQLAlchemyMiddleware, db_url=str(main_settings.orchestrator_database_url))


# include routers
app.include_router(user_router)
