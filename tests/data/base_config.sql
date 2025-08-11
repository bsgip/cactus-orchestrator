
-- Users
INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
VALUES ('user1', 'https://test-cactus-issuer.example.com', E'\\x01', E'\\x02', E'\\x03', E'\\x04');
INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
VALUES ('user2', 'https://test-cactus-issuer.example.com', NULL, NULL, NULL, NULL);
INSERT INTO user_ (subject_id, issuer_id, aggregator_certificate_p12_bundle, aggregator_certificate_x509_der, device_certificate_p12_bundle, device_certificate_x509_der)
VALUES ('user3', 'https://test-cactus-issuer.example.com', E'\\x', E'\\x', E'\\x', E'\\x');

-- 
INSERT INTO run_group (user_id, name, csip_aus_version) VALUES (1, 'name-1', 'v1.2');
INSERT INTO run_group (user_id, name, csip_aus_version) VALUES (1, 'name-2', 'v1.3-beta/storage');
INSERT INTO run_group (user_id, name, csip_aus_version) VALUES (2, 'name-3', 'v1.2');


INSERT INTO run (run_group_id, teststack_id, testprocedure_id, created_at, finalised_at, run_status, all_criteria_met)
VALUES 
(1, 'teststack1', 'ALL-01', '2024-01-01T00:01:00Z', NULL, 1, NULL), -- run_id 1
(1, 'teststack2', 'ALL-01', '2024-01-01T00:02:00Z', '2024-01-02T00:02:00Z', 3, TRUE), -- run_id 2
(1, 'teststack3', 'ALL-02', '2024-01-01T00:03:00Z', '2024-01-02T00:03:00Z', 4, TRUE), -- run_id 3
(1, 'teststack4', 'ALL-03', '2024-01-01T00:04:00Z', '2024-01-02T00:04:00Z', 5, FALSE), -- run_id 4
(2, 'teststack5', 'ALL-01', '2024-01-01T00:05:00Z', NULL, 2, NULL), -- run_id 5
(3, 'teststack6', 'GEN-02', '2024-01-01T00:06:00Z', NULL, 1, NULL), -- run_id 6
(1, 'teststack7', 'ALL-04', '2024-01-01T00:07:00Z', '2024-01-02T00:07:00Z', 3, FALSE), -- run_id 7
(1, 'teststack8', 'ALL-05', '2024-01-01T00:08:00Z', NULL, 2, NULL); -- run_id 8