import dataclasses
from http import HTTPStatus

import pytest
from assertical.asserts.type import assert_list_type
from assertical.fake.generator import generate_class_instance
from cactus_schema.orchestrator import (
    ComplianceRequestRequest,
    ComplianceRequestResponse,
    ComplianceRequestUpdateRequest,
    uri,
)


@pytest.mark.asyncio
async def test_get_compliance_requests_paginated(client, pg_compliance_config, valid_jwt_user1):
    # Act
    res = await client.get(uri.ComplianceRequestList, headers={"Authorization": f"Bearer {valid_jwt_user1}"})

    assert res.status_code == HTTPStatus.OK

    data = res.json()
    assert isinstance(data, dict)
    assert "items" in data
    requests = [ComplianceRequestResponse.from_dict(i) for i in data["items"]]

    assert_list_type(ComplianceRequestResponse, requests, 2)


@pytest.mark.parametrize(
    "user_id, compliance_request_id, expected_status", [(2, 1, HTTPStatus.OK), (2, 2, HTTPStatus.OK)]
)
@pytest.mark.asyncio
async def test_get_compliance_request(
    user_id: int, compliance_request_id: int, expected_status: HTTPStatus, client, pg_compliance_config, valid_jwt_user1
):
    def user_id_to_jwt(id: int):
        if id == 2:
            return valid_jwt_user1
        raise ValueError()

    # Act
    res = await client.get(
        uri.ComplianceRequest.format(compliance_request_id=compliance_request_id),
        headers={"Authorization": f"Bearer {user_id_to_jwt(user_id)}"},
    )

    assert res.status_code == expected_status
    request = ComplianceRequestResponse.from_json(res.text)
    # 'from_json' can return lists but we know that this GET request should return just one compliance request
    assert not isinstance(request, list)
    assert request.compliance_request_id == compliance_request_id


@pytest.mark.asyncio
async def test_create_compliance_request(client, pg_compliance_config, valid_jwt_user1):
    # Arrange
    request_params = generate_class_instance(ComplianceRequestRequest)
    assert isinstance(request_params, ComplianceRequestRequest)

    # Act
    res = await client.post(
        uri.ComplianceRequestList,
        headers={"Authorization": f"Bearer {valid_jwt_user1}"},
        content=request_params.to_json(),
    )

    assert res.status_code == HTTPStatus.CREATED
    request = ComplianceRequestResponse.from_json(res.text)
    # 'from_json' can return lists but we know that creating a compliance request can only return one
    # value
    assert not isinstance(request, list)

    assert request.compliance_request_id == 4
    # compare each field of values passed create (request_params) with the same values
    # return by POST (request)
    for field in dataclasses.fields(request_params):
        assert getattr(request_params, field.name) == getattr(request, field.name)


@pytest.mark.asyncio
async def test_update_compliance_request(client, pg_compliance_config, valid_jwt_user1):
    # Arrange
    request_params = generate_class_instance(ComplianceRequestUpdateRequest)
    attrs_to_set_none = ["der_brand", "der_oem", "der_series", "der_representative_models"]
    for attr in attrs_to_set_none:
        setattr(request_params, attr, None)

    assert isinstance(request_params, ComplianceRequestUpdateRequest)
    compliance_request_id = 1

    # Act
    res = await client.put(
        uri.ComplianceRequest.format(compliance_request_id=compliance_request_id),
        headers={"Authorization": f"Bearer {valid_jwt_user1}"},
        content=request_params.to_json(),
    )

    # Assert
    assert res.status_code == HTTPStatus.OK
