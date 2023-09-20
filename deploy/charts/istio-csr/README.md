# cert-manager-istio-csr

![Version: v0.7.1](https://img.shields.io/badge/Version-v0.7.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.7.1](https://img.shields.io/badge/AppVersion-v0.7.1-informational?style=flat-square)

istio-csr enables the use of cert-manager for issuing certificates in Istio service meshes

**Homepage:** <https://github.com/cert-manager/istio-csr>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| cert-manager-maintainers | <cert-manager-maintainers@googlegroups.com> | <https://cert-manager.io> |

## Source Code

* <https://github.com/cert-manager/istio-csr>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| app.certmanager.additionalAnnotations | list | `[]` | Additional annotations to include on certificate requests. Takes key/value pairs in the format:   - name: custom.cert-manager.io/policy-name     value: istio-csr |
| app.certmanager.issuer.group | string | `"cert-manager.io"` | Issuer group name set on created CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs. |
| app.certmanager.issuer.kind | string | `"Issuer"` | Issuer kind set on created CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs. |
| app.certmanager.issuer.name | string | `"istio-ca"` | Issuer name set on created CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs. |
| app.certmanager.namespace | string | `"istio-system"` | Namespace to create CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs. |
| app.certmanager.preserveCertificateRequests | bool | `false` | Don't delete created CertificateRequests once they have been signed. WARNING: do not enable this option in production, or environments with any non-trivial number of workloads for an extended period of time. Doing so will balloon the resource consumption of both ETCD and the API server, leading to errors and slow down. This option is intended for debugging purposes only, for limited periods of time. |
| app.controller.configmapNamespaceSelector | string | `nil` | If set, limit where istio-csr creates configmaps with root ca certificates. If unset, configmap created in ALL namespaces. Example: maistra.io/member-of=istio-system |
| app.controller.leaderElectionNamespace | string | `"istio-system"` |  |
| app.istio.namespace | string | `"istio-system"` | The namespace where the istio control-plane is running. |
| app.istio.revisions | list | `["default"]` | The istio revisions that are currently installed in the cluster. Changing this field will modify the DNS names that will be requested for the istiod certificate. The common name for the istiod certificate is hard coded to the `default` revision DNS name. Some issuers may require that the common name on certificates match one of the DNS names. If 1. Your issuer has this constraint, and 2. You are not using `default` as a revision, add the `default` revision here anyway. The resulting certificate will include a DNS name that won't be used, but will pass this constraint. |
| app.logLevel | int | `1` | Verbosity of istio-csr logging. |
| app.metrics.port | int | `9402` | Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'. |
| app.metrics.service | object | `{"enabled":true,"servicemonitor":{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"},"type":"ClusterIP"}` | Service to expose metrics endpoint. |
| app.metrics.service.enabled | bool | `true` | Create a Service resource to expose metrics endpoint. |
| app.metrics.service.servicemonitor | object | `{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"}` | ServiceMonitor resource for this Service. |
| app.metrics.service.type | string | `"ClusterIP"` | Service type to expose metrics. |
| app.readinessProbe.path | string | `"/readyz"` | Path to expose istio-csr HTTP readiness probe on default network interface. |
| app.readinessProbe.port | int | `6060` | Container port to expose istio-csr HTTP readiness probe on default network interface. |
| app.server.clusterID | string | `"Kubernetes"` | The istio cluster ID to verify incoming CSRs. |
| app.server.maxCertificateDuration | string | `"1h"` | Maximum validity duration that can be requested for a certificate. istio-csr will request a duration of the smaller of this value, and that of the incoming gRPC CSR. Based on NIST 800-204A recommendations (SM-DR13). https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf |
| app.server.serving.address | string | `"0.0.0.0"` | Container address to serve istio-csr gRPC service. |
| app.server.serving.certificateKeySize | int | `2048` | Number of bits to use for the server's serving certificate (RSAKeySize). |
| app.server.serving.certificateUsages | list | `["server auth"]` | List of certificate usages for the server's serving certificate. |
| app.server.serving.port | int | `6443` | Container port to serve istio-csr gRPC service. |
| app.server.serving.signatureAlgorithm | string | `"RSA"` | The type of signature algorithm to use when generating private keys. Currently only RSA and ECDSA are supported. By default RSA is used. |
| app.tls.certificateDNSNames | list | `["cert-manager-istio-csr.cert-manager.svc"]` | The DNS names to request for the server's serving certificate which is presented to istio-agents. istio-agents must route to istio-csr using one of these DNS names. |
| app.tls.certificateDuration | string | `"1h"` | Requested duration of gRPC serving certificate. Will be automatically renewed. Based on NIST 800-204A recommendations (SM-DR13). https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf |
| app.tls.certificateUsages | list | `[]` | The reported X.509 and extended key usages to be matched against the key usage set. Required when using a RAM shared AWS Private CA |
| app.tls.istiodCertificateDuration | string | `"1h"` | Requested duration of istio's Certificate. Will be automatically renewed. Based on NIST 800-204A recommendations (SM-DR13). https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf Warning: cert-manager does not allow a duration on Certificates less than 1 hour. |
| app.tls.istiodCertificateEnable | bool | `true` |  |
| app.tls.istiodCertificateRenewBefore | string | `"30m"` |  |
| app.tls.istiodPrivateKeySize | int | `2048` |  |
| app.tls.rootCAFile | string | `nil` | An optional file location to a PEM encoded root CA that the root CA ConfigMap in all namespaces will be populated with. If empty, the CA returned from cert-manager for the serving certificate will be used. |
| app.tls.trustDomain | string | `"cluster.local"` | The Istio cluster's trust domain. |
| image.pullPolicy | string | `"IfNotPresent"` | Kubernetes imagePullPolicy on Deployment. |
| image.repository | string | `"quay.io/jetstack/cert-manager-istio-csr"` | Target image repository. |
| image.tag | string | `"v0.7.1"` | Target image version tag. |
| imagePullSecrets | list | `[]` | Optional secrets used for pulling the istio-csr container image. |
| nodeSelector | object | `{}` |  |
| replicaCount | int | `1` | Number of replicas of istio-csr to run. |
| resources | object | `{}` |  |
| service.port | int | `443` | Service port to expose istio-csr gRPC service. |
| service.type | string | `"ClusterIP"` | Service type to expose istio-csr gRPC service. |
| tolerations | list | `[]` |  |
| volumeMounts | list | `[]` | Optional extra volume mounts. Useful for mounting custom root CAs |
| volumes | list | `[]` | Optional extra volumes. Useful for mounting custom root CAs |

