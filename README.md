# client-csip-test-harness-k8s-management

Web API for management of the k8s platform.

Current implementation relies on 'template' resources (defined in yaml) to be created, which are then cloned as requests come in.

Core resources are:
- envoy StatefulSet: This is the complete envoy deployment including envoy app, envoy admin app, db and pubsub components. This is a templated resource.
- envoy Service: This is created alongside the envoy statefulset and is what we route requests to. This is a templated resource.
- mTLS Ingress: We use nginx-ingress. This component handles mTLS and cert forwarding for the testing namespace.
- TLS Ingress: TODO, this is for the management api.

mTLS Ingress Certifcates:
- Custom CA cert/key pair: Used for signing client certs, these are stored in seperate k8s Secrets. The cacert is referenced in the Ingress spec for client certificate validation.
- Server cert/key pair: Signed by above, these are stored in a single tls secret and referenced in Ingress spec.
- Client cert/key pair: Created and signed on the fly as part of requests to the management API.

TODO/NOTES:
- Consider creating everything from scratch i.e. not using templates.
- Once use case is clear, consider a more modern+typed k8s client library.
- We may no longer need StatefulSets and can rely on Pods directly.
- Consider service mesh for transparent encryption of pod-to-pod comms.
- Background task for teardown on long idle.