# cert-manager-istio-csr

![Version: v0.1.3](https://img.shields.io/badge/Version-v0.1.3-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.1.3](https://img.shields.io/badge/AppVersion-v0.1.3-informational?style=flat-square)

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
| app.certmanager.issuer.group | string | `"cert-manager.io"` | Issuer group name set on created CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs. |
| app.certmanager.issuer.kind | string | `"Issuer"` | Issuer kind set on created CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs. |
| app.certmanager.issuer.name | string | `"istio-ca"` | Issuer name set on created CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs. |
| app.certmanager.namespace | string | `"istio-system"` | Namespace to create CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs. |
| app.certmanager.preserveCertificateRequests | bool | `false` | Don't delete created CertificateRequests once they have been signed. |
| app.controller.leaderElectionNamespace | string | `"istio-system"` |  |
| app.controller.rootCAConfigMapName | string | `"istio-ca-root-cert"` | Name of ConfigMap that should contain the root CA in all namespaces. |
| app.logLevel | int | `1` | Verbosity of istio-csr logging. |
| app.readinessProbe.path | string | `"/readyz"` | Path to expose istio-csr HTTP readiness probe on default network interface. |
| app.readinessProbe.port | int | `6060` | Container port to expose istio-csr HTTP readiness probe on default network interface. |
| app.server.clusterID | string | `"Kubernetes"` | The istio cluster ID to verify incoming CSRs. |
| app.server.maxCertificateDuration | string | `"24h"` | Maximum validity duration that can be requested for a certificate. istio-csr will request a duration of the smaller of this value, and that of the incoming gRPC CSR. |
| app.server.serving.address | string | `"0.0.0.0"` | Container address to serve istio-csr gRPC service. |
| app.server.serving.port | int | `6443` | Container port to serve istio-csr gRPC service. |
| app.tls.certificateDNSNames | list | `["cert-manager-istio-csr.cert-manager.svc"]` | The DNS names to request for the server's serving certificate which is presented to istio-agents. istio-agents must route to istio-csr using one of these DNS names. |
| app.tls.certificateDuration | string | `"24h"` | Requested duration of gRPC serving certificate. Will be automatically renewed. |
| app.tls.rootCAFile | string | `nil` | An optional file location to a PEM encoded root CA that the root CA ConfigMap in all namespaces will be populated with. If empty, the CA returned from cert-manager for the serving certificate will be used. |
| app.tls.trustDomain | string | `"cluster.local"` | The Istio cluster's trust domain. |
| image.pullPolicy | string | `"IfNotPresent"` | Kubernetes imagePullPolicy on Deployment. |
| image.repository | string | `"quay.io/jetstack/cert-manager-istio-csr"` | Target image repository. |
| image.tag | string | `"v0.1.3"` | Target image version tag. |
| replicaCount | int | `1` | Number of replicas of istio-csr to run. |
| resources | object | `{}` |  |
| service.port | int | `443` | Service port to expose istio-csr gRPC service. |
| service.type | string | `"ClusterIP"` | Service type to expose istio-csr gRPC service. |
| volumeMounts | list | `[]` | Optional extra volume mounts. Useful for mounting custom root CAs |
| volumes | list | `[]` | Optional extra volumes. Useful for mounting custom root CAs |

