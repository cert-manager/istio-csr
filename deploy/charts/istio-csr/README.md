# cert-manager-istio-csr

![Version: v0.1.0](https://img.shields.io/badge/Version-v0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.1.0](https://img.shields.io/badge/AppVersion-v0.1.0-informational?style=flat-square)

A Helm chart for istio-csr

**Homepage:** <https://github.com/jetstack/istio-csr>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| joshvanl | joshua.vanleeuwen@jetstack.io | https://cert-manager.io |

## Source Code

* <https://github.com/cert-manager/istio-csr>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| agent.certificateDuration | string | `"24h"` | Requested duration of gRPC serving certificate. Will be automatically renewed. |
| agent.logLevel | int | `1` | Verbosity of istio-csr logging. |
| agent.readinessProbe.path | string | `"/readyz"` | Path to expose istio-csr HTTP readiness probe on default network interface. |
| agent.readinessProbe.port | int | `6060` | Container port to expose istio-csr HTTP readiness probe on default network interface. |
| agent.rootCAConfigMapName | string | `"istio-ca-root-cert"` | Name of ConfigMap that should contain the root CA in all namespaces. |
| agent.servingAddress | string | `"0.0.0.0"` | Container address to serve istio-csr gRPC service. |
| agent.servingPort | int | `6443` | Container port to serve istio-csr gRPC service. |
| certificate.group | string | `"cert-manager.io"` | Issuer group name set on created CertificateRequests from incoming gRPC CSRs. |
| certificate.kind | string | `"Issuer"` | Issuer kind set on created CertificateRequests from incoming gRPC CSRs. |
| certificate.maxDuration | string | `"24h"` | Maximum validity duration that can be requested for a certificate. istio-csr will request a duration of the smaller of this value, and that of the incoming gRPC CSR. |
| certificate.name | string | `"istio-ca"` | Issuer name set on created CertificateRequests from incoming gRPC CSRs. |
| certificate.namespace | string | `"istio-system"` | Namespace to create CertificateRequests from incoming gRPC CSRs. |
| certificate.preserveCertificateRequests | bool | `false` | Don't delete created CertificateRequests once they have been signed. |
| certificate.rootCA | string | `nil` | An optional PEM encoded root CA that the root CA ConfigMap in all namespaces will be populated with. If empty, the CA returned from cert-manager for the serving certificate will be used. |
| image.pullPolicy | string | `"IfNotPresent"` | Kubernetes imagePullPolicy on Deployment. |
| image.repository | string | `"quay.io/jetstack/cert-manager-istio-csr"` | Target image repository. |
| image.tag | string | `"v0.1.0"` | Target image version tag. |
| replicaCount | int | `1` | Number of replicas of istio-csr to run. |
| resources | object | `{}` |  |
| service.port | int | `443` | Service port to expose istio-csr gRPC service. |
| service.type | string | `"ClusterIP"` | Service type to expose istio-csr gRPC service. |

