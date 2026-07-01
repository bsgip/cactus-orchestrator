
-- Users
INSERT INTO user_ (subject_id, issuer_id, pen, user_name, subscription_domain)
VALUES ('user1', 'https://test-cactus-issuer.example.com', 64, 'user1@cactus.example.com', 'user1.example.com');
INSERT INTO user_ (subject_id, issuer_id, pen, user_name, subscription_domain)
VALUES ('user2', 'https://test-cactus-issuer.example.com', 64, 'user2@cactus.example.com', 'user2.example.com');
INSERT INTO user_ (subject_id, issuer_id, pen, user_name)
VALUES ('user3', 'https://test-cactus-issuer.example.com', 64, NULL);

-- Run Groups
INSERT INTO run_group (user_id, name, csip_aus_version, is_device_cert, certificate_pem, certificate_generated_at, certificate_id, is_static_uri)
VALUES (1, 'name-1', 'v1.2', TRUE, E'\\x01', '2023-01-01T00:01:00Z', 11, FALSE);
INSERT INTO run_group (user_id, name, csip_aus_version, is_device_cert, certificate_pem, certificate_generated_at, certificate_id, is_static_uri)
VALUES (1, 'name-2', 'v1.3-beta/storage', NULL, NULL, NULL, 0, TRUE);
INSERT INTO run_group (user_id, name, csip_aus_version, is_device_cert, certificate_pem, certificate_generated_at, certificate_id, is_static_uri)
VALUES (2, 'name-3', 'v1.2', FALSE, E'\\x03', '2023-01-01T00:03:00Z', 33, FALSE);


INSERT INTO run_artifact (compression, file_data) VALUES ('gzip', E'\\x0001');
INSERT INTO run_artifact (compression, file_data) VALUES ('gzip', E'\\x0002');
INSERT INTO run_artifact (compression, file_data) VALUES ('gzip', E'\\x0003');

INSERT INTO run (run_group_id, run_artifact_id, pod_name, testprocedure_id, created_at, finalised_at, run_status, all_criteria_met)
VALUES 
(1, NULL, 'run-1', 'ALL-01', '2024-01-01T00:01:00Z', NULL, 1, NULL), -- run_id 1
(1, 1, 'run-2', 'ALL-01', '2024-01-01T00:02:00Z', '2024-01-02T00:02:00Z', 3, TRUE), -- run_id 2
(1, NULL, 'run-3', 'ALL-02', '2024-01-01T00:03:00Z', '2024-01-02T00:03:00Z', 4, TRUE), -- run_id 3
(1, 2, 'run-4', 'ALL-03', '2024-01-01T00:04:00Z', '2024-01-02T00:04:00Z', 5, FALSE), -- run_id 4
(2, 3, 'run-5', 'ALL-01', '2024-01-01T00:05:00Z', NULL, 2, NULL), -- run_id 5
(3, NULL, 'run-6', 'GEN-02', '2024-01-01T00:06:00Z', NULL, 1, NULL), -- run_id 6
(1, NULL, 'run-7', 'ALL-04', '2024-01-01T00:07:00Z', '2024-01-02T00:07:00Z', 3, FALSE), -- run_id 7
(1, NULL, 'run-8', 'ALL-05', '2024-01-01T00:08:00Z', NULL, 2, NULL); -- run_id 8



