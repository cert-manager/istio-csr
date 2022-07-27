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
