# This is still **WIP / DRAFT**

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




## (1) Preparing k8s manifests
First we need to apply some configurations to the template manifests provided.
1. Define a .env file with the following vars:
```
APP_ENVOY_IMAGE='<registry>/<image-name>:<tag>'
APP_HARNESS_RUNNER_IMAGE='<registry>/<image-name>:<tag>'
ORCHESTRATOR_K8S_MANAGER_IMAGE='<registry>/<image-name>:<tag>'
TESTING_FQDN='<subdomain>.<domain>.<tld>'
USER_FQDN='<subdomain>.<domain>.<tld>'
```

2. A script `templates-to-manifests.sh' is provided to copy the setup template directory and then apply all the above environment variables to k8s manifests templates. Script usage:
```
./templates-to-manfests.sh ./setup <destination-dir> <.env file>
```


## Cluster configuration (./cluster-setup)
On the control node
1. Apply at-rest-encryption to the microk8s secret store. Run the `setup-encryption.sh` script.

2. We make two namespaces (1) for test pods (2) for management pods:
```
microk8s kubectl create namespace test-pods
microk8s kubectl create namespace management
```
3. Define management service account in management namespace. This has permissions to create and destroy resources, will be used my are
harness-orchestrator/management pods.
```
microk8s apply -f management-service-account.yaml -n management
```
4. Add private image registry to each namespace (kubectl approach):
(1) test-pods namespace
```
microk8s kubectl create secret docker-registry acr-token --docker-server=<somereg.io> --docker-username="<token-name>" --docker-password="<token-pwd>" --namespace test-pods

microk8s kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "acr-token"}]}' --namespace <some-namespace>
```
(2) management namespace. NOTE: difference is service account name
```
microk8s kubectl create secret docker-registry acr-token --docker-server=<somereg.io> --docker-username="<token-name>" --docker-password="<token-pwd>" --namespace management

microk8s kubectl patch serviceaccount pod-creator -p '{"imagePullSecrets": [{"name": "acr-token"}]}' --namespace management
```
5. Setup test-pod ingress

5. Add custom CA secrets. The CA needs two secrets (1) for use by Ingress which only holdes the CA cert (2) is the CA cert and key, used for signing client certs.
TODO
## K8s resource setup (./app)





