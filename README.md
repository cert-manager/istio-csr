<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>
<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/istio-csr">
    <img src="https://godoc.org/github.com/cert-manager/istio-csr?status.svg">
  </a>
  <a href="https://goreportcard.com/report/github.com/cert-manager/istio-csr">
    <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/istio-csr" />
  </a>
  <a href="https://artifacthub.io/packages/search?repo=cert-manager">
    <img alt="artifact hub badge" src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager">
  </a>
</p>

# istio-csr

istio-csr is an agent that allows for [Istio](https://istio.io) workload and
control plane components to be secured using
[cert-manager](https://cert-manager.io).

Certificates facilitating mTLS &mdash; both inter
and intra-cluster &mdash; will be signed, delivered and renewed using [cert-manager
issuers](https://cert-manager.io/docs/concepts/issuer).

istio-csr supports Istio v1.10+ and cert-manager v1.3+

---

## Documentation

Please follow the documentation at
[cert-manager.io](https://cert-manager.io/docs/usage/istio/) for installing and
using istio-csr.

## Release Process

The release process is documented in [RELEASE.md](RELEASE.md).

## Inner workings

istio-csr has 3 main components: the TLS certificate obtainer, the gRPC server and the CA bundle distributor.
1. The TLS certificate obtainer is responsible for obtaining the TLS certificate for the gRPC server.
It uses the cert-manager API to create a CertificateRequest resource, which will be picked up by cert-manager and signed by the configured issuer.
2. The gRPC server is responsible for receiving certificate signing requests from istiod and sending back the signed certificate.
Herefore, it uses the cert-manager CertificateRequest API to obtain the signed certificate.
3. The CA bundle distributor is responsible for creating and updating istio-ca-root-cert ConfigMaps in all namespaces (filtered using namespaceSelector).

## Istio Ambient

When istio-csr is being deployed into Istio Ambient, the `--ca-trusted-node-accounts` flag must be set with the `<namespace>/<service-account-name>` of ztunnel, eg. `istio-system/ztunnel`.
This allows ztunnel to authenticate using its own identity, then request certificates for the identity it will impersonate. For more information on how ztunnel handles certificate, see the Istio Ambient [docs](https://github.com/istio/istio/blob/master/architecture/ambient/ztunnel.md).
