# istio-csr

cert-manager-istio-csr is an agent which allows for [istio](https://istio.io) workload
and control plane components to be secured using
[cert-manager](https://cert-manager.io). Certificates facilitating mTLS, inter
and intra cluster, will be signed, delivered and renewed using [cert-manager
issuers](https://cert-manager.io/docs/concepts/issuer).

Currently supports istio versions v1.7 and v1.8

---

## Installation

Firstly, [cert-manager must be
installed](https://cert-manager.io/docs/installation/) in your cluster. An
issuer must be configured, which will be used to sign your certificate
workloads, as well a ready Certificate to serve istiod. Example Issuer and
istiod Certificate configuration can be found in
[`./hack/demo/cert-manager-bootstrap-resources.yaml`](./hack/demo/cert-manager-bootstrap-resources.yaml).

Next, install the cert-manager-istio-csr into the cluster, configured to use
the Issuer deployed. The Issuer must reside in the same namespace as that
configured by `-c, --certificate-namespace`, which is `istio-system` by default.

```bash
$ helm repo add https://chart.jetstack.io
$ helm repo update
$ helm install -n cert-manager cert-manager-istio-csr
```

All helm value options can be found in
[here](./deploy/charts/istio-csr/README.md).

Finally, install istio. Istio must be installed using the IstioOperator
configuration changes within
[`./hack/istio-config-x.yaml`](./hack/istio-config-1.8.2.yaml). These changes are
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
