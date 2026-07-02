-- Users
INSERT INTO user_ (subject_id, issuer_id, pen, user_name)
VALUES
('user1', 'https://test-cactus-issuer.example.com', 64, 'user1@cactus.example.com'),
('user2', 'https://test-cactus-issuer.example.com', 64, 'user2@cactus.example.com'),
('user3', 'https://test-cactus-issuer.example.com', 64, 'user3@cactus.example.com'),
('admin1', 'https://test-cactus-issuer.example.com', 64, 'admin1@cactus.example.com'),
('admin2', 'https://test-cactus-issuer.example.com', 64, 'admin2@cactus.example.com');

-- Run Groups
INSERT INTO run_group (user_id, name, csip_aus_version, is_device_cert, certificate_pem, certificate_generated_at, certificate_id)
VALUES
(1, 'user-1-device-1', 'v1.2', TRUE, '\x01', '2023-01-01T00:01:00Z', 11),
(1, 'user-1-device-2', 'v1.3-beta/storage', NULL, NULL, NULL, 0),
(2, 'user-2-device-1', 'v1.2', TRUE, '\x01', '2023-01-01T00:01:00Z', 11),
(3, 'user-3-device-1', 'v1.2', TRUE, '\x01', '2023-01-01T00:01:00Z', 11);

-- Runs
INSERT INTO run (run_group_id, run_artifact_id, teststack_id, testprocedure_id, created_at, finalised_at, run_status, all_criteria_met)
VALUES 
(1, NULL, 'teststack1', 'ALL-03', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 1
(1, NULL, 'teststack1', 'OPT-1-IN-BAND', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 2
(1, NULL, 'teststack1', 'OPT-1-OUT-OF-BAND', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 3
(1, NULL, 'teststack1', 'ALL-26', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 4
(1, NULL, 'teststack1', 'ALL-27', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 5
(1, NULL, 'teststack1', 'ALL-28', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 6
(1, NULL, 'teststack1', 'ALL-29', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 7
(1, NULL, 'teststack1', 'ALL-30', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 8
(3, NULL, 'teststack1', 'ALL-30', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 9
(4, NULL, 'teststack1', 'ALL-30', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true); -- run_id 10

-- Compliance Records
INSERT INTO compliance_record (run_group_id, requester_id, created_at)
VALUES
(1, 3, '2025-11-24T12:30Z');



-- Compliance Requests
INSERT INTO compliance_request (created_at, created_by, updated_at, updated_by, status, csip_aus_version, witnessed_at, der_brand, der_oem, der_series, der_representative_models, software_client_type, software_client_providers, software_client_versions, onsite_hardware_details)
VALUES
(
	'2026-05-04T13:15Z',
	1,
	'2026-05-04T13:15Z',
	1,
	4,
	'v1.2',
	'2026-05-01T15:30Z',
	'der_brand',
	'der_oem',
	'der_series',
	'der_representative_models',
	'software_client_type',
	'software_client_providers',
	'software_client_versions',
	'onsite_hardware_details'
),  -- compliance_request_id 1
(
	'2026-05-07T09:09Z',
	1,
	'2026-05-07T09:09Z',
	1,
	1,
	'v1.2',
	'2026-05-02T00:00Z',
	'der_brand',
	'der_oem',
	'der_series',
	'der_representative_models',
	'software_client_type',
	'software_client_providers',
	'software_client_versions',
	'onsite_hardware_details'
),  -- compliance_request_id 2
(
	'2026-05-07T07:09Z',
	2,
	'2026-05-07T07:09Z',
	2,
	1,
	'v1.2',
	'2026-05-02T00:00Z',
	'der_brand',
	'der_oem',
	'der_series',
	'der_representative_models',
	'software_client_type',
	'software_client_providers',
	'software_client_versions',
	'onsite_hardware_details'
),  -- compliance_request_id 3
(
	'2026-05-07T07:09Z',
	3,  -- user 3
	'2026-05-07T07:09Z',
	2,
	1,
	'v1.2',
	'2026-05-02T00:00Z',
	'der_brand',
	'der_oem',
	'der_series',
	'der_representative_models',
	'software_client_type',
	'software_client_providers',
	'software_client_versions',
	'onsite_hardware_details'
);  -- compliance_request_id 4

-- Compliance Request Classes
INSERT INTO compliance_request_class (compliance_request_id, compliance_class)
VALUES
(1, 'L'),
(1, 'DER-A'),
(1, 'S-G'), -- end of compliance request 1 
(2, 'L'),
(2, 'DER-A'),
(2, 'S-G'), -- end of compliance request 2
(3, 'A'), -- end of compliance request 3
(4, 'A'); -- end of compliance request 4

-- Compliance Request Runs
INSERT INTO compliance_request_run (compliance_request_id, compliance_run_id)
VALUES
(1, 1),
(1, 3),
(1, 5), -- end of compliance request 1
(2, 1),
(2, 3),
(2, 5), -- end of compliance request 2
(3, 9), -- end of compliance request 3
(4, 10); -- end of compliance request 3

INSERT INTO compliance_request_finalisation (compliance_request_id, created_at, created_by, file_data)
VALUES
(1, '2026-05-04T13:15Z', 4, '\\x0001'),  -- compliance for user 1 (created by admin 1)
(4, '2026-05-04T13:15Z', 4, '\\x0004');  -- compliance for user 3 (created by admin 1)

