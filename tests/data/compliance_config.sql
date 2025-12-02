
-- Users
INSERT INTO user_ (subject_id, issuer_id, pen, user_name)
VALUES ('admin1', 'https://test-cactus-issuer.example.com', 64, 'admin1@cactus.example.com');
INSERT INTO user_ (subject_id, issuer_id, pen, user_name)
VALUES ('user1', 'https://test-cactus-issuer.example.com', 64, 'user1@cactus.example.com');

-- Run Groups
INSERT INTO run_group (user_id, name, csip_aus_version, is_device_cert, certificate_pem, certificate_generated_at, certificate_id)
VALUES (2, 'device-1', 'v1.2', TRUE, E'\\x01', '2023-01-01T00:01:00Z', 11);
INSERT INTO run_group (user_id, name, csip_aus_version, is_device_cert, certificate_pem, certificate_generated_at, certificate_id)
VALUES (2, 'device-2', 'v1.3-beta/storage', NULL, NULL, NULL, 0);

-- Runs
INSERT INTO run (run_group_id, run_artifact_id, teststack_id, testprocedure_id, created_at, finalised_at, run_status, all_criteria_met)
VALUES 
(1, NULL, 'teststack1', 'ALL-03', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 1
(1, NULL, 'teststack1', 'OPT-1-IN-BAND', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 1
(1, NULL, 'teststack1', 'OPT-1-OUT-OF-BAND', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 1
(1, NULL, 'teststack1', 'ALL-26', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 2
(1, NULL, 'teststack1', 'ALL-27', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 3
(1, NULL, 'teststack1', 'ALL-28', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 4
(1, NULL, 'teststack1', 'ALL-29', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true), -- run_id 5
(1, NULL, 'teststack1', 'ALL-30', '2024-01-01T00:01:00Z', '2024-01-01T01:01:00Z', 4, true); -- run_id 6

-- Compliance Records
INSERT INTO compliance_record (run_group_id, requester_id, created_at)
VALUES
(1, 1, '2025-11-24T12:30Z')

