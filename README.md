<p align="center">
  <img src="https://raw.githubusercontent.com/jetstack/cert-manager/master/logo/logo.png" width="250x" alt="cert-manager project logo" />
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

istio-csr supports Istio v1.7+ and cert-manager v1.3+

---

## Getting Started Guide For istio-csr

We have [a guide](./docs/getting_started.md) for setting up istio-csr in a fresh [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) cluster.

Following the guide is the best way to see istio-csr in action.

If you've already seen istio-csr in action or if you're experienced with running Istio and just want quick installation instructions, read on for more details.

## Lower-Level Details (For Experienced Istio Users)

⚠️  The [getting started](./docs/getting_started.md) guide is a better place if you just want to try istio-csr out!

Running istio-csr requires a few steps and preconditions in order:

1. A cluster _without_ Istio already installed
2. cert-manager [installed](https://cert-manager.io/docs/installation/) in the cluster
3. An `Issuer` or `ClusterIssuer` which will be used to issue Istio certificates
4. istio-csr installed (likely via helm)
5. Istio [installed](https://istio.io/latest/docs/setup/install/istioctl/) with some custom config required, e.g. using [the example config](./docs/istio-config-getting-started.yaml).

### Why Custom Istio Install Manifests?

If you take a look at the contents of [the example Istio install manifest](./docs/istio-config-getting-started.yaml) there are a few
custom configuration options which are important.

Required changes include setting `ENABLE_CA_SERVER` to `false` and setting the `caAddress` from which Istio will
request certificates; replacing the CA server is the whole point of istio-csr!

Mounting and statically specifying the root CA is also an important recommended step. Without a manually specified
root CA istio-csr defaults to trying to discover root CAs automatically, which could theoretically lead to a
[signer hijacking attack](https://github.com/cert-manager/istio-csr/issues/103#issuecomment-923882792) if for example
a signer's token was stolen (such as the cert-manager controller's token).

### Issuer or ClusterIssuer?

Unless you know you need a `ClusterIssuer` we'd recommend starting with an `Issuer`, since it should be easier to reason about
the access controls for an Issuer; they're namespaced and so naturally a little more limited in scope.

That said, if you view your entire Kubernetes cluster as being a trust domain itself, then a ClusterIssuer is the more natural
fit. The best choice will depend on your specific situation.

Our [getting started guide](./docs/getting_started.md) uses an `Issuer`.

### Which Issuer Type?

Whether you choose to use an `Issuer` or a `ClusterIssuer`, you'll also need to choose the type of issuer you want such as:

- [CA](https://cert-manager.io/docs/configuration/ca/)
- [Vault](https://cert-manager.io/docs/configuration/vault/)
- or an [external issuer](https://cert-manager.io/docs/configuration/external/)

The key requirement is that arbitrary values can be placed into the `subjectAltName` (SAN) X.509 extension, since
Istio places SPIFFE IDs there.

That means that the ACME issuer **will not work** &mdash; publicly trusted certificates such as those issued by Let's Encrypt
don't allow arbitrary entries in the SAN, for very good reasons.

If you're already using [Hashicorp Vault](https://www.vaultproject.io/) then the Vault issuer is an obvious choice. If
you want to control your own PKI entirely, we'd recommend the CA issuer. The choice is ultimately yours.

### Installing istio-csr After Istio

This is unsupported because it's exceptionally difficult to do safely. It's likely that installing istio-csr _after_ Istio isn't
possible to do without downtime, since installing istio-csr second would require a time period where all Istio sidecars trust
both the old Istio-managed CA and the new cert-manager controlled CA.

## How Does istio-csr Work?

istio-csr implements the gRPC Istio certificate service which authenticates, authorizes, and signs incoming certificate signing requests from Istio workloads, routing all certificate handling through cert-manager installed in the cluster.

This seamlessly matches the behaviour of istiod in a typical installation, while allowing certificate management through cert-manager.
