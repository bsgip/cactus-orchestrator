# This is still **WIP / DRAFT**

Intention is for these manifest templates to be configured using environment variables and `envsubst`.



## microk8s cluster-setup
Getting started:
1. install microk8s on all nodes: https://microk8s.io/docs/getting-started
2. On the designated control plane node, run `microk8s add-node` and follow instructions returned to add other nodes to the cluster.

### configuration
1. Secret encryption:
TODO
2. Enable addons:
```
microk8s enable ingress

microk8s enable dns
```
3. We make two namespaces (1) for test pods (2) for management pods:
```
microk8s kubectl create namespace test-pods
microk8s kubectl create namespace management
```
4. Management service account. This has permissions to create and destroy resources.


4. Add Azure private image registry to each namespace (kubectl approach):
(1) test-pods namespace
```
microk8s kubectl create secret docker-registry acr-token --docker-server=<somereg.io> --docker-username="<token-name>" --docker-password="<token-pwd>" --namespace test-pods

microk8s kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "acr-token"}]}' --namespace <some-namespace>
```
(2) management namespace. NOTE: the difference is there is a service

5. Add custom CA secrets. The CA needs two secrets (1) for use by Ingress which only holdes the CA cert (2) is the CA cert and key, used for signing client certs.
TODO