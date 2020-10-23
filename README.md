# istio-csr

cert-manager-istio-agent is an agent which allows for [istio](istio.io) workload
and control plane components to be secured using
[cert-manager](https://cert-manager.io). Certificates facilitating mTLS, inter
and intra cluster, will be signed, delivered and renewed using [cert-manager
issuers](https://cert-manager.io/docs/concepts/issuer).

Currently supports istio v1.7

---

## Installation

Firstly, [cert-manager must be
installed](https://cert-manager.io/docs/installation/) in your cluster. An
issuer must be configured, which will be used to sign your certificate
workloads, as well a ready Certificate to serve istiod. Example Issuer and
istiod Certificate configuration can be found in
[`./hack/demo/cert-manager-bootstrap-resources.yaml`](./hack/demo/cert-manager-bootstrap-resources.yaml).

Next, install the cert-manager-istio-agent into the cluster, configured to use
the Issuer deployed.

```bash
$ helm install cert-manager-istio-demo ./deploy/charts/istio-csr -n cert-manager
```

Finally, install istio. Istio must be installed using the IstioOperator
configuration changes within
[`./hack/istio-config.yaml`](./hack/istio-config.yaml). These changes are
required in order for the CA Server to be disabled in istiod, ensure istio
workloads request certificates from the cert-manager agent, and the istiod
certificates and keys are mounted in from the Certificate created earlier.


## How

The cert-manager istio agent implements the gRPC istio certificate service,
which authenticates, authorizes, and signs incoming certificate signing requests
from istio workloads. This matches the behaviour of istiod in a typical
installation, however enables these certificates to be signed through
cert-manager.

---

## Testing

To run the end to end tests, run;

```bash
$ make e2e
```
