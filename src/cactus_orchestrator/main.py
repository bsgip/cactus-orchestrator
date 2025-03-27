from fastapi import FastAPI
from fastapi_async_sqlalchemy import SQLAlchemyMiddleware
from fastapi_pagination import add_pagination
from fastapi.middleware.gzip import GZipMiddleware

from cactus_orchestrator.api import procedure_router, run_router, user_router
from cactus_orchestrator.settings import main_settings
from cactus_orchestrator.tasks import lifespan


app = FastAPI(lifespan=lifespan)

# middleware
app.add_middleware(SQLAlchemyMiddleware, db_url=str(main_settings.orchestrator_database_url), commit_on_exit=False)
add_pagination(app)
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)

# include routers
app.include_router(user_router)
app.include_router(run_router)
app.include_router(procedure_router)
