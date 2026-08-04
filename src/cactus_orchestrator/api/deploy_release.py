import logging
from typing import Annotated

from cactus_schema.orchestrator import DeployReleaseResponse, uri
from fastapi import APIRouter, Depends
from fastapi_async_sqlalchemy import db

from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.crud import select_deploy_releases

logger = logging.getLogger(__name__)


router = APIRouter()

DEPLOY_RELEASE_LIMIT = 20


@router.get(uri.DeployReleaseList)
async def fetch_deploy_releases(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> list[DeployReleaseResponse]:
    """The most recent deploys of this environment"""
    deploy_releases = await select_deploy_releases(db.session, DEPLOY_RELEASE_LIMIT)
    return [DeployReleaseResponse(release_tag=d.release_tag, created_at=d.created_at) for d in deploy_releases]
