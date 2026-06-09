# cactus-orchestrator

Web API for management of the podman platform and orchestration of test execution environments.


## Environment Variables

| Environment Variable | Default Value | Description |
|----------------------|----------------|-------------|
| `KUBERNETES_LOAD_CONFIG` | `true` | For testing only. Set to `false` to skip loading Kubernetes configuration. |
| `TEST_ORCHESTRATION_NAMESPACE` | `test-orchestration` | Namespace used by the cactus-orchestrator components. |
| `ORCHESTRATOR_DATABASE_URL` | – | SQLAlchemy-style database connection string using `postgresql+asyncpg` scheme. |
| `TEST_EXECUTION_NAMESPACE` | `test-execution` | Namespace used for live cactus teststack instances (cactus-runner, envoy, etc.). |
| `TEST_EXECUTION_INGRESS_NAME` | `test-execution-ingress` | Name of the ingress resource managing external access to teststack instances. |
| `TESTSTACK_SERVICE_PORT` | `80` | Port exposed by the Kubernetes `Service` for teststack instances. |
| `TESTSTACK_TEMPLATES_NAMESPACE` | `teststack-templates` | Namespace where teststack templates are stored. |
| `TEMPLATE_SERVICE_NAME` | `envoy-svc` | Name of the templated Kubernetes `Service`. |
| `TEMPLATE_APP_NAME` | `envoy` | Name of the main app (container) defined in the template. |
| `TEMPLATE_STATEFULSET_NAME` | `envoy-set` | Name of the templated StatefulSet for deploying teststack instances. |
| `TLS_CA_CERTIFICATE_GENERIC_SECRET_NAME` | `tls-ca-certificate` | Name of the generic secret that stores the CA certificate used for client certificate validation. |
| `TLS_CA_TLS_SECRET_NAME` | `tls-ca-cert-key-pair` | Name of the TLS secret that holds the CA certificate and key used to sign client certificates. |
| `TEST_EXECUTION_FQDN` | – | Fully qualified domain name for accessing test execution instances. |
| `IDLETEARDOWNTASK_ENABLE` | `true` | Enables the background task that tears down idle teststack instances. |
| `IDLETEARDOWNTASK_MAX_LIFETIME_SECONDS` | `86400` | Maximum lifetime (in seconds) allowed for a teststack instance. |
| `IDLETEARDOWNTASK_IDLE_TIMEOUT_SECONDS` | `3600` | Time (in seconds) after last interaction before an instance is considered idle. |
| `IDLETEARDOWNTASK_REPEAT_EVERY_SECONDS` | `120` | Frequency (in seconds) at which the idle teardown task runs. |
| `IGNORED_CSIP_AUS_VERSIONS` | `[]` | JSON Encoded list of strings - what CSIP-Aus versions to be removed/ignored from the supported version list |


## rooful podman setup

The test pods will be assigned unique hostnames which requires a rootful podman setup

```bash
# Enable the rootful podman socket
sudo systemctl enable --now podman.socket

# Verify the socket is active
sudo systemctl status podman.socket
sudo ls -la /run/podman/podman.sock

# Allow your user to access it via new group "podman"
sudo groupadd podman
sudo usermod -aG podman $USER
sudo chown root:podman /run/podman/
sudo chown root:podman /run/podman/podman.sock
sudo chmod 770 /run/podman/podman.sock

# Then export in your shell profile 
# This will make all podman commands use the root socket rather than your user socket
echo 'export CONTAINER_HOST=unix:///run/podman/podman.sock' >> ~/.bashrc
source ~/.bashrc

# The podman.sock will be recreated every restart - to make the socket group permanent
sudo mkdir -p /etc/systemd/system/podman.socket.d
sudo tee /etc/systemd/system/podman.socket.d/override.conf <<EOF
[Socket]
SocketGroup=podman
SocketMode=0770

[Service]
RuntimeDirectoryMode=0770
EOF
sudo systemctl daemon-reload
sudo systemctl restart podman.socket
```


## Database-related
- Only tested with **PostgreSQL 16**.
- Uses **SQLAlchemy with asyncpg**.
- **Alembic** manages schema migrations, with scripts located under [`./alembic`](./alembic).
- Database connection is configured via the `ORCHESTRATOR_DATABASE_URL` environment variable.
- Migrations are not run automatically; apply manually as part of deployment.

## TODO / Notes

- Consider dynamically generating all resources instead of relying on pre-defined templates.
- Evaluate adoption of a modern, typed Kubernetes client library.
- Investigate replacing StatefulSets with regular Pods if persistent identity is no longer needed.

