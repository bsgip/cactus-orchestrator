# cactus-orchestrator

Web API for management of the Kubernetes platform and orchestration of test execution environments.

The current implementation relies on 'template' resources (defined in YAML) that are cloned into active instances as requests come in.

## Core Resources

- **teststack StatefulSet resource**: Templated resource that defines the Pod running the teststack components (envoy, envoy-admin, db, pubsub, etc.).
- **teststack Service resource**: A templated `Service` resource created alongside the StatefulSet, used to route requests to the teststack Pod.
- **mTLS Ingress resource**: An NGINX-based ingress controller configured for mutual TLS. It handles certificate forwarding and client authentication in the `test-execution` namespace.
- **TLS Ingress resource**: *TODO* — This will secure the orchestrator API itself.

## mTLS Ingress Certificates

- **Custom CA cert/key pair**: Used to sign client certificates. These are stored as separate Kubernetes `Secrets`. The CA certificate is referenced in the Ingress spec for client certificate validation.
- **Server cert/key pair**: Signed by the custom CA above. Stored in a single TLS secret and referenced in the Ingress.
- **Client cert/key pair**: Generated and signed dynamically for each request to the orchestrator API.



# Nomenclature

- **teststack instance**: A full deployment of the cactus test environment, composed of:
  - A Kubernetes `Service` resource (for routing)
  - A Kubernetes `StatefulSet` resource that runs a single `Pod`  consisting of multiple containers:
    - **cactus-runner**: The main engine responsible for executing tests.
    - **envoy**: A network proxy used for routing and traffic control within the teststack.
    - **envoy-admin**: An administrative interface for Envoy, used for inspection, debugging, and dynamic configuration.
    - **envoy-db**: The database component used by Envoy for storing state and configuration.
    - **subscription/notification**: Components enabling Envoy’s pub/sub functionality, such as pushing updates or results.

- **template**: A pre-created Kubernetes resource (StatefulSet, Service, etc.) stored in a dedicated namespace and used as a blueprint for launching new teststack instances.

- **test-execution namespace**: The namespace in which active teststack instances are created and managed.

- **test-orchestration namespace**: The namespace where the cactus-orchestrator and cactus-ui components run.

- **teststack template namespace**: The namespace where the reusable resource templates for teststack instances are stored.

- **mTLS Ingress**: An NGINX-based ingress configured for mutual TLS, securing traffic between clients and teststack instances.

- **TLS Ingress**: A planned ingress for securing access to the Cactus orchestrator and UI components.

- **idle teardown**: A background task that identifies and tears down inactive or long-lived teststack instances to free up resources.

---

# Environment Variables

| Environment Variable | Default Value | Description |
|----------------------|----------------|-------------|
| `KUBERNETES_LOAD_CONFIG` | `true` | For testing only. Set to `false` to skip loading Kubernetes configuration. |
| `TEST_ORCHESTRATION_NAMESPACE` | `test-orchestration` | Namespace used by the cactus-orchestrator components. |
| `ORCHESTRATOR_DATABASE_URL` | – | SQLAlchemy-style database connection string. |
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

---
## TODO / Notes

- Consider dynamically generating all resources instead of relying on pre-defined templates.
- Evaluate adoption of a modern, typed Kubernetes client library.
- Investigate replacing StatefulSets with regular Pods if persistent identity is no longer needed.
- Consider introducing a service mesh to transparently encrypt pod-to-pod communication.

