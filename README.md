# cactus-orchestrator

Web API for management of the podman platform and orchestration of test execution environments.


## Environment Variables

| Environment Variable | Default Value | Description |
|----------------------|----------------|-------------|
| `ORCHESTRATOR_DATABASE_URL` | – | SQLAlchemy-style database connection string using `postgresql+asyncpg` scheme. |
| `CACTUS_FQDN` | – | Fully qualified domain name that the service is hosted under. Test pods will run as a subdomain of this. |
| `ENVOY_PREFIX` | `/envoy` | href prefix that envoy will be hosted under (allows for upstream routing to be filtered to just this prefix). |
| `COMMS_TIMEOUT_SECONDS` | 120 | Backend timeout when proxying requests to test pods |
| `PODMAN_SOCKET` | `/run/podman/podman.sock` | Path to rootful podman socket - will be used to create test pods |
| `PODMAN_NETWORK` | `cactus-net` | Name of a pre-existing podman bridge network that test pods will operate under |
| `PODMAN_RUNNER_PORT` | `8080` | The exposed port in each test pod that will route to the cactus-runner test harness |
| `CACTUS_IMAGE__XXX__CSIP_AUS_VERSION` * | – | Replace `XXX` with a version tag - The full CSIP-Aus version tag |
| `CACTUS_IMAGE__XXX__POSTGRES` * | – | Replace `XXX` with a version tag - The postgres image for version `XXX` |
| `CACTUS_IMAGE__XXX__INIT` * | – | Replace `XXX` with a version tag - The db migration script image for version `XXX` |
| `CACTUS_IMAGE__XXX__ENVOY` * | – | Replace `XXX` with a version tag - The envoy image for version `XXX` |
| `CACTUS_IMAGE__XXX__RUNNER` * | – | Replace `XXX` with a version tag - The runner image for version `XXX` |

| `CERT_SERCA_PATH` | – | Path on disk to the SERCA ca.crt PEM file - used for showing server signing chain |
| `CERT_DEVICE_MCA_PATH` | – | Path on disk to the MCA ca.crt PEM file - used for showing server signing chain - should be the signing cert for device MICA |
| `CERT_DEVICE_MICA_CRT_PATH` | – | Path on disk to the MICA tls.crt PEM file - used for generating new client DEVICE certs |
| `CERT_DEVICE_MICA_KEY_PATH` | – | Path on disk to the MICA tls.key PEM file - used for generating new client DEVICE certs |
| `CERT_AGG_PCA_PATH` | – | Path on disk to the PCA ca.crt PEM file - used for showing server signing chain - should be the signing cert for agg ICA |
| `CERT_AGG_ICA_CRT_PATH` | – | Path on disk to the ICA tls.crt PEM file - used for generating new client AGGREGATOR certs |
| `CERT_AGG_ICA_KEY_PATH` | – | Path on disk to the ICA tls.key PEM file - used for generating new client AGGREGATOR certs |
| `CERT_ENVOY_EE_FULLCHAIN_PATH` | – | Path on disk to the cert bundle (PEM encoded) file - used by utility server instances when establishing a mTLS subscription/notification conection |
| `CERT_ENVOY_EE_KEY_PATH` | – | Path on disk to the tls.key PEM file - used by utility server instances when establishing a mTLS subscription/notification conection |
| `IDLETEARDOWNTASK_ENABLE` | `True` | If `True` - Start a background service for monitoring idle/old test pods |
| `IDLETEARDOWNTASK_MAX_LIFETIME_SECONDS` | `3600 * 24 * 4` | Test runs older than this will be destroyed |
| `IDLETEARDOWNTASK_IDLE_TIMEOUT_SECONDS` | `3600 * 2` | Test runs with no comms for longer than this will be destroyed |
| `IDLETEARDOWNTASK_REPEAT_EVERY_SECONDS` | `120` | Check for idle test runs at this frequency |
| `IDLETEARDOWNTASK_STARTUP_GRACE_SECONDS` | `300` | A pod must be at least this old before it can be declared an orphan |


| `PULLTASK_REPEAT_EVERY_SECONDS` | `120` | Check for unpulled podman images at this frequency |
| `IGNORED_CSIP_AUS_VERSIONS` | - | JSON encoded list of strings - each representing a CSIP-Aus version to be ignored |
| `IGNORED_TEST_PROCEDURES` | - | JSON encoded list of strings - each representing a TestProcedureID to be ignored |

```
# * All image versions work together as a series of blocks eg:

CACTUS_IMAGE__V1_99__CSIP_AUS_VERSION = "v1.99"
CACTUS_IMAGE__V1_99__POSTGRES = "postgres:123"
CACTUS_IMAGE__V1_99__INIT = "init-script:123"
CACTUS_IMAGE__V1_99__ENVOY = "envoy:123"
CACTUS_IMAGE__V1_99__RUNNER = "runner:123"

CACTUS_IMAGE__V1_2__CSIP_AUS_VERSION" = "v1.2"
CACTUS_IMAGE__V1_2__POSTGRES = "postgres:456"
CACTUS_IMAGE__V1_2__INIT = "init-script:456"
CACTUS_IMAGE__V1_2__ENVOY = "envoy:456"
CACTUS_IMAGE__V1_2__RUNNER = "runner:456"
```

## rootful podman setup

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
sudo tee /etc/tmpfiles.d/podman.conf <<EOF
d /run/podman 0770 root podman - -
EOF

# Apply immediately without rebooting
sudo systemd-tmpfiles --create /etc/tmpfiles.d/podman.conf

sudo mkdir -p /etc/systemd/system/podman.socket.d
sudo tee /etc/systemd/system/podman.socket.d/override.conf <<EOF
[Socket]
SocketGroup=podman
SocketMode=0770
EOF
sudo systemctl daemon-reload
sudo systemctl restart podman.socket
```


## DB Setup

Create DB and DB user
```
sudo -u postgres psql
postgres=# create database cactusorchestrator;
postgres=# create user cactususer with encrypted password 'mypass';
postgres=# grant all privileges on database cactusorchestrator to cactususer;
postgres=# alter database cactusorchestrator owner to cactususer;
```

Apply alembic migrations
```
export ORCHESTRATOR_DATABASE_URL="postgresql+asyncpg://cactususer:mypass@localhost:5432/cactusorchestrator"
uv run alembic upgrade head
```

## Logging

Running pods will write to journald - to access logs:

```
# Logs for a whole pod
journalctl CONTAINER_TAG=run-123

# Logs for a specific container
journalctl CONTAINER_TAG=run-123 CONTAINER_NAME=run-123-envoy
```