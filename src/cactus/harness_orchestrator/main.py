from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi_cache import FastAPICache
from fastapi_cache.backends.inmemory import InMemoryBackend
from fastapi_async_sqlalchemy import SQLAlchemyMiddleware

from cactus.harness_orchestrator.api.user import router as user_router
from cactus.harness_orchestrator.settings import main_settings, init_k8s_config


init_k8s_config()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    FastAPICache.init(InMemoryBackend(), prefix="fastapi-cache")
    yield


app = FastAPI(lifespan=lifespan)


app.add_middleware(SQLAlchemyMiddleware, db_url=str(main_settings.orchestrator_database_url))


# include routers
app.include_router(user_router)
