# Local development — orchestrator + UI from source

Run `cactus-orchestrator` and `cactus-ui` as plain host processes with live reload, IDE breakpoints, real podman pods. 
No traefik, nginx, or client-notifications included.

Setting `DEV_RUNNER_LOCALHOST_PORT_BASE` makes orchestrator publish pod's on `127.0.0.1` port and hit it via localhost 
instead of pod-name DNS (which only works inside `cactus-net`). **Never set this in production!!**

This runs as non root to keep vscode debugger happy.

Assumes Ubuntu 24.04 (or any Linux with rootful podman ≥ 4.9 on netavark).

## 1. Podman, network, socket access

```bash
sudo apt install -y podman
sudo systemctl enable --now podman.socket

# Pod DNS requires netavark. Fresh 24.04 defaults to it; a box upgraded from 22.04 can be
# stuck on cni — if so:
# printf '[network]\nnetwork_backend = "netavark"\n' | sudo tee /etc/containers/containers.conf.d/netavark.conf
podman info --format '{{.Host.NetworkBackend}}'        # must say: netavark

sudo podman network create cactus-net                  # skip if it exists
sudo podman network inspect cactus-net --format 'dns={{.DNSEnabled}}'   # must say: dns=true

# Let your user talk to the rootful socket. Resets on reboot — re-run if you get "permission denied".
sudo chmod 755 /run/podman && sudo chmod 666 /run/podman/podman.sock
podman --url unix:///run/podman/podman.sock version    # verify, as your normal user
```

Optional, to survive reboots instead of re-running the chmods:

```bash
sudo mkdir -p /etc/systemd/system/podman.socket.d
printf '[Socket]\nSocketMode=0666\nDirectoryMode=0755\n' | \
    sudo tee /etc/systemd/system/podman.socket.d/local-dev.conf
sudo systemctl daemon-reload && sudo systemctl restart podman.socket
```

(Restarting `podman.socket` invalidates the old socket handle — if a traefik container is
running against it, `sudo podman rm -f traefik` so it gets recreated.)

## 2. Postgres on the host

Host postgres (not a container) so restoring dumps from the test server is easy.

```bash
sudo apt install -y postgresql
sudo -u postgres psql -c "CREATE ROLE cactus LOGIN PASSWORD 'cactus'" -c "CREATE DATABASE cactusorchestrator OWNER cactus"
PGPASSWORD=cactus psql -h 127.0.0.1 -U cactus -d cactusorchestrator -c "select 1"   # verify

# Load real data later:
#   ssh test-server pg_dump -Fc ... > dump && pg_restore -h 127.0.0.1 -U cactus -d cactusorchestrator dump
```

## 3. Throwaway PKI

The orchestrator requires signing-chain files at startup. Generate dev-only certs:

```bash
uv run python local-dev/generate_dev_pki.py            # from the repo root
```

`--fqdn` defaults to `cactus.local.test` — must match `CACTUS_FQDN` in your env file.

## 4. Teststack images

The pull images we need (check cactus-deploy versions.lock for the latest names):

```bash
sudo podman pull cactusimageregistry.azurecr.io/cactus-db:174-v12
sudo podman pull cactusimageregistry.azurecr.io/cactus-envoy:174-v12
sudo podman pull cactusimageregistry.azurecr.io/cactus-runner:174-v12
```

## 5. Orchestrator — migrate, run, debug

```bash
cp local-dev/sample.env local-dev/orchestrator.env
# edit orchestrator.env: 
# JWTAUTH_* (Auth0 dev tenant, from the dev server's cactus.env),
# CERT_* path prefixes,
# image tags to match §4
```

From the repo root:

```bash
uv sync --all-extras
uv run --env-file local-dev/orchestrator.env alembic upgrade head
uv run --env-file local-dev/orchestrator.env --with 'uvicorn==0.48.0' uvicorn --reload --port 8080 cactus_orchestrator.main:app
```

Sanity check: `curl -i http://127.0.0.1:8080/procedure` → **401**

OR run same thing from your debugger:
`module: uvicorn`, `args: ["--port", "8080", "cactus_orchestrator.main:app"]`
`envFile: ${workspaceFolder}/local-dev/orchestrator.env`,
interpreter `.venv`.

## 6. UI

Following `cactus-ui/README.md` ("Running locally") with: 
CACTUS_ORCHESTRATOR_BASEURL="http://localhost:8080" and `AUTH0_*` dev-tenant creds. 

`http://localhost:3000/callback` must be in the Auth0 Allowed Callback URLs.

```bash
uv run python src/cactus_ui/server.py   # Flask backend on :3000
cd frontend && npm run dev              # Vite on :5173  - develop here
```

## 7. Simulating the DER client (curl / Postman)

**A real DER client can't connect to this dev instance.** In production, nginx terminates mTLS and injects the client 
cert into the `ssl-client-cert` header. Locally runner speaks plain HTTP on a localhost port, you supply that header.

Find a pod's runner port:

```bash
sudo podman ps                          # PORTS column shows e.g. 127.0.0.1:20042->8080/tcp
# or, per pod (bindings live on the pod's infra container, not the runner container):
sudo podman pod inspect run-42 --format '{{.InfraConfig.PortBindings}}'
curl -i http://127.0.0.1:<port>/health       # HTTP 200, empty body (503 = unhealthy)
```

The runner's API is `/health`, `/status`, `/initialise`, `/start`, `/finalize`.
Envoy is proxied under the `ENVOY_PREFIX` prefix (default `/envoy`, per orchestrator settings): `/envoy/dcap`,
`/envoy/edev`, etc. On every proxied request set the `ssl-client-cert` header to the **url-encoded contents** of the
run's cert (the `fullchain.pem` from the UI's cert download ZIP works as-is — the leaf is first and the LFDI
computation only reads the first cert):

```bash
curl http://127.0.0.1:<port>/envoy/dcap \
  -H "ssl-client-cert: $(python3 -c "import urllib.parse; print(urllib.parse.quote(open('fullchain.pem').read()))")"
```

Proxied responses: 400 = no active test procedure (initialise/start a run first), 403 = cert doesn't match the
run's registered cert, 200 = through to envoy.

In Postman: set a collection-level `ssl-client-cert` header. No TLS client cert config needed.

**Future state:** for true mTLS with a real client, the pods already carry traefik labels. Just need to spin up
traefik plus nginx per cactus-deploy `server/`. That needs resolvable `rg-*.{CACTUS_FQDN}` DNS and full cert staging.

## Limitations / gotchas

- **`DEV_RUNNER_LOCALHOST_PORT_BASE` is local-dev-only — never set it in production.**
- `IDLETEARDOWNTASK_ENABLE=false` (the sample default) is required only when another
  orchestrator shares the podman host — the task destroys any cactus pod it can't find in
  *its own* database. On a dedicated machine, set it true to auto-clean abandoned pods;
  with it false, clean up manually: `sudo podman pod rm -f <name>`.
- The `https://rg-....cactus.local.test` run URLs shown in the UI don't resolve — reach
  runners via their localhost port (§7).
- Socket permissions (§1) reset on reboot unless you added the systemd override.
