import logging
from functools import partial

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi_async_sqlalchemy import SQLAlchemyMiddleware
from fastapi_pagination import add_pagination

from cactus_orchestrator.api import procedure_router, run_router, user_router
from cactus_orchestrator.settings import CactusOrchestratorSettings, get_current_settings
from cactus_orchestrator.tasks import lifespan

# Setup logs
logging.basicConfig(style="{", level=logging.DEBUG)
logger = logging.getLogger(__name__)


def generate_app(new_main_settings: CactusOrchestratorSettings) -> FastAPI:

    app = FastAPI(lifespan=partial(lifespan, settings=new_main_settings))

    # middleware
    app.add_middleware(
        SQLAlchemyMiddleware, db_url=str(new_main_settings.orchestrator_database_url), commit_on_exit=False
    )
    add_pagination(app)
    app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)

    # include routers
    app.include_router(user_router)
    app.include_router(run_router)
    app.include_router(procedure_router)

    return app


app = generate_app(get_current_settings())
