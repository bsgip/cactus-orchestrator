# This is still **WIP / DRAFT**
TODO:
- Anything related to the Harness UI is yet to be decided
- Better namespace names

## (1) Cluster creation
Getting started (Ubuntu 24.04):
0. Setup and harden using standard scripts.
1. Install microk8s on all nodes: https://microk8s.io/docs/getting-started
2. Make a k8suser on the control node, add them to `sudo` group.
3. QoL, so you don't have to keep typing `microk8s kubectl`, add the following to `/home/k8suser/.bashrc`:
```
alias k8s="microk8s kubectl"
source <(microk8s kubectl completion bash)
complete -o default -F __start_kubectl k8s
```
4. On the designated control plane node, run `microk8s add-node` and follow instructions returned to add other nodes (as workers) to the cluster.
5. Enable the following addons:
```
microk8s enable ingress dns
```
6. Enable the load balancer addon: `microk8s enable metallb`. It will request an ip-range for the load balancer, we should only need one. Give it the free static IP you want to expose for as for your FQDN.

## (2) Preparing k8s manifests
microk8s/kubernetes has no out-of-the-box utility for configurable yaml manifests. We instead use a custom script which relies on `envsubst` to substitute variables.

1. Make a working directory `mkdir /home/k8suser/k8s-cluster/`.

2. Define a .env file with the following vars:
```
APP_ENVOY_IMAGE='<registry>/<image-name>:<tag>'
APP_HARNESS_RUNNER_IMAGE='<registry>/<image-name>:<tag>'
ORCHESTRATOR_K8S_MANAGER_IMAGE='<registry>/<image-name>:<tag>'
TESTING_FQDN='<subdomain>.<domain>.<tld>'
USER_FQDN='<subdomain>.<domain>.<tld>'
```

2. The `templates-to-manifests.sh' script is provided to copy the deploy-template directory and apply environment variables to the k8s manifests templates. Script usage:
```
./templates-to-manfests.sh ./deploy-template /home/k8suser/k8s-cluster/deploy/ /home/k8suser/k8s-cluster/.env
```

## Cluster configuration (./cluster-setup)
1. Apply at-rest-encryption to the microk8s secret store. Run the `setup-encryption.sh` script.

2. We make two namespaces (1) for test pods (2) for management pods:
```
microk8s kubectl create namespace testing
microk8s kubectl create namespace management
```
3. Define management service account in management namespace. This has permissions to create and destroy resources, will be used my are
harness-orchestrator/management pods.
```
microk8s apply -f management-service-account.yaml -n management
```
4. Add private image registry to each namespace (kubectl approach):
(1) testing namespace
```
microk8s kubectl create secret docker-registry acr-token --docker-server=<somereg.io> --docker-username="<token-name>" --docker-password="<token-pwd>" --namespace testing

microk8s kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "acr-token"}]}' --namespace <some-namespace>
```
(2) management namespace. NOTE: difference is service account name
```
microk8s kubectl create secret docker-registry acr-token --docker-server=<somereg.io> --docker-username="<token-name>" --docker-password="<token-pwd>" --namespace management

microk8s kubectl patch serviceaccount pod-creator -p '{"imagePullSecrets": [{"name": "acr-token"}]}' --namespace management
```
5. Create the ingress load-balancer service and ingress resources
```
microk8s kubectl apply -f ./ingress/load-balancer-svc.yml -n ingress
microk8s kubectl apply -f ./ingress/testing-ingress.yml -n testing
# TODO: microk8s kubectl apply -f ./ingress/user-interface-ingress.yml -n ?
```

6. Add custom CA secrets. The CA needs two secrets (1) for use by Ingress which only holdes the CA cert (2) is the CA cert and key, used for signing client certs.
```
k8s create secret generic -n testing tls-ca-certificate --from-file=ca.crt=<path-to-ca.crt>
k8s create secret tls tls-ca-cert-key-pair -n testing --cert <path-to-ca.crt> --key <path-to-unencrypted-ca.key>
```

7. Add server certificate/key secrets.
```
# for testing ingress
ingress/install-server-certs.sh --cert </path/to/cert.crt> --key </path/to/key.key> --namespace testing --ingress testing-ingress

# TODO: for user-interface ingress
```
## K8s resource setup (./app-setup)
1. We create the harness-orchestrator service. This manages the on-demand creation and deletion of the full envoy 'test environment' stack.
```
microk8s kubectl apply -f harness-orchestrator -n management
```

2. We currently create 'template' resources that represent the envoy test environments. These are cloned on request for a client test environment to be created. Lets create these template resources:
```
microk8s kubectl apply -f envoy-environment -n testing
```





