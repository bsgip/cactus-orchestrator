import asyncio
import dataclasses
import logging
from http import HTTPStatus
from typing import Annotated

from cactus_schema.orchestrator import (
    ComplianceRequestRequest,
    ComplianceRequestResponse,
    ComplianceRequestUpdateRequest,
    uri,
)
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi_async_sqlalchemy import db
from fastapi_pagination import Page, paginate
from sqlalchemy.exc import NoResultFound

from cactus_orchestrator.api.common import map_to_compliance_request_response, select_user_or_raise
from cactus_orchestrator.auth import AuthPerm, UserContext, jwt_validator
from cactus_orchestrator.crud import (
    insert_compliance_request,
    safe_delete_compliance_request,
    select_user_compliance_request,
    select_user_compliance_request_finalisation,
    select_user_compliance_requests,
    update_compliance_request,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(uri.ComplianceRequestArtifact, status_code=HTTPStatus.OK)
async def get_compliance_request_artifact(
    compliance_request_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Response:
    user = await select_user_or_raise(
        db.session,
        user_context,
    )

    finalisation = await select_user_compliance_request_finalisation(
        session=db.session, user_id=user.user_id, compliance_request_id=compliance_request_id
    )

    if finalisation is None or finalisation.file_data is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found")

    return Response(
        status_code=HTTPStatus.OK,
        content=finalisation.file_data,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=ComplianceReport-{compliance_request_id}.pdf"},
    )


@router.get(uri.ComplianceRequestList, status_code=HTTPStatus.OK)
async def get_compliance_requests_paginated(
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Page[ComplianceRequestResponse]:
    # check permissions
    user = await select_user_or_raise(
        db.session,
        user_context,
    )

    # get compliance requests
    requests = await select_user_compliance_requests(db.session, user.user_id)

    if requests:
        awaitables = [map_to_compliance_request_response(request) for request in requests]
        resp = await asyncio.gather(*awaitables)
    else:
        resp = []
    return paginate(resp)


@router.get(uri.ComplianceRequest, status_code=HTTPStatus.OK)
async def get_compliance_request(
    compliance_request_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> ComplianceRequestResponse:

    # check permissions
    user = await select_user_or_raise(db.session, user_context)

    # get compliance request
    try:
        request = await select_user_compliance_request(
            session=db.session,
            user_id=user.user_id,
            compliance_request_id=compliance_request_id,
        )
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found") from exc

    return await map_to_compliance_request_response(request)


@router.post(uri.ComplianceRequestList, status_code=HTTPStatus.CREATED)
async def create_compliance_request(
    body: ComplianceRequestRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> ComplianceRequestResponse:
    user = await select_user_or_raise(db.session, user_context)

    request = await insert_compliance_request(
        session=db.session,
        created_by=user.user_id,
        csip_aus_version=body.csip_aus_version,
        witnessed_at=body.witnessed_at,
        classes=body.classes,
        runs=body.runs,
        der_brand=body.der_brand,
        der_oem=body.der_oem,
        der_series=body.der_series,
        der_representative_models=body.der_representative_models,
        software_client_type=body.software_client_type,
        software_client_providers=body.software_client_providers,
        software_client_versions=body.software_client_versions,
        onsite_hardware_details=body.onsite_hardware_details,
    )

    await db.session.commit()

    return await map_to_compliance_request_response(request)


# update_compliance_request
@router.put(uri.ComplianceRequest, status_code=HTTPStatus.OK)
async def update_compliance_request_endpoint(
    compliance_request_id: int,
    body: ComplianceRequestUpdateRequest,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> ComplianceRequestResponse:
    user = await select_user_or_raise(db.session, user_context)

    # get compliance request
    try:
        request = await select_user_compliance_request(
            session=db.session,
            user_id=user.user_id,
            compliance_request_id=compliance_request_id,
        )
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found") from exc

    # Determine which parameters to update (these have a value that isn't None)
    params = {
        field.name: getattr(body, field.name)
        for field in dataclasses.fields(body)
        if getattr(body, field.name) is not None
    }

    await update_compliance_request(session=db.session, updated_by=user.user_id, compliance_request=request, **params)

    await db.session.commit()
    return await map_to_compliance_request_response(request)


# delete_compliance_request
@router.delete(uri.ComplianceRequest, status_code=HTTPStatus.OK)
async def delete_compliance_request_endpoint(
    compliance_request_id: int,
    user_context: Annotated[UserContext, Depends(jwt_validator.verify_jwt_and_check_perms({AuthPerm.user_all}))],
) -> Response:
    user = await select_user_or_raise(db.session, user_context)

    # get compliance request
    try:
        request = await select_user_compliance_request(
            session=db.session,
            user_id=user.user_id,
            compliance_request_id=compliance_request_id,
        )
    except NoResultFound as exc:
        logger.debug(exc)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not Found") from exc

    try:
        request_deletable = await safe_delete_compliance_request(session=db.session, compliance_request=request)
    except Exception as exc:
        logger.debug(exc)
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail="Failed to delete compliance request"
        ) from exc

    if not request_deletable:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Compliance Request has been finalised. Unable to delete."
        )

    await db.session.commit()
    return Response(status_code=HTTPStatus.OK)
