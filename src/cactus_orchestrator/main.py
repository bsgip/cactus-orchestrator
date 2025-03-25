from fastapi import FastAPI
from fastapi_async_sqlalchemy import SQLAlchemyMiddleware
from fastapi_pagination import add_pagination

from cactus_orchestrator.api import procedure_router, run_router, user_router
from cactus_orchestrator.settings import load_k8s_config, main_settings
from cactus_orchestrator.tasks import lifespan

# NOTE: This needs to be called before instantiating any of the k8s clients
load_k8s_config()

app = FastAPI(lifespan=lifespan)

# middleware
app.add_middleware(SQLAlchemyMiddleware, db_url=str(main_settings.orchestrator_database_url), commit_on_exit=False)
add_pagination(app)

# include routers
app.include_router(user_router)
app.include_router(run_router)
app.include_router(procedure_router)
