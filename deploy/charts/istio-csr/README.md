# cert-manager-istio-csr

istio-csr enables the use of cert-manager for issuing certificates in Istio service meshes

**Homepage:** <https://cert-manager.io/docs/usage/istio-csr/>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| cert-manager-maintainers | <cert-manager-dev@googlegroups.com> | <https://cert-manager.io> |

## Source Code

* <https://github.com/cert-manager/istio-csr>

## Values

<!-- AUTO-GENERATED -->


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>replicaCount</td>
<td>

Number of replicas of istio-csr to run.

</td>
<td>number</td>
<td>

```yaml
1
```

</td>
</tr>
<tr>

<td>image.repository</td>
<td>

Target image repository.

</td>
<td>string</td>
<td>

```yaml
quay.io/jetstack/cert-manager-istio-csr
```

</td>
</tr>
<tr>

<td>image.registry</td>
<td>

Target image registry. Will be prepended to the target image repository if set.

</td>
<td>unknown</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>image.tag</td>
<td>

Target image version tag. Defaults to the chart's appVersion.

</td>
<td>unknown</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>image.digest</td>
<td>

Target image digest. Will override any tag if set.  
For example:

```yaml
digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```

</td>
<td>unknown</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>image.pullPolicy</td>
<td>

Kubernetes imagePullPolicy on Deployment.

</td>
<td>string</td>
<td>

```yaml
IfNotPresent
```

</td>
</tr>
<tr>

<td>imagePullSecrets</td>
<td>

Optional secrets used for pulling the istio-csr container image.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>service.type</td>
<td>

Service type to expose istio-csr gRPC service.

</td>
<td>string</td>
<td>

```yaml
ClusterIP
```

</td>
</tr>
<tr>

<td>service.port</td>
<td>

Service port to expose istio-csr gRPC service.

</td>
<td>number</td>
<td>

```yaml
443
```

</td>
</tr>
<tr>

<td>app.logLevel</td>
<td>

Verbosity of istio-csr logging.

</td>
<td>number</td>
<td>

```yaml
1
```

</td>
</tr>
<tr>

<td>app.metrics.port</td>
<td>

Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'.

</td>
<td>number</td>
<td>

```yaml
9402
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor</td>
<td>

Create a Service resource to expose metrics endpoint.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor</td>
<td>

Service type to expose metrics.

</td>
<td>string</td>
<td>

```yaml
ClusterIP
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.enabled</td>
<td>

Create Prometheus ServiceMonitor resource for approver-policy.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.prometheusInstance</td>
<td>

The value for the "prometheus" label on the ServiceMonitor. This allows for multiple Prometheus instances selecting difference ServiceMonitors using label selectors.

</td>
<td>string</td>
<td>

```yaml
default
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.interval</td>
<td>

The interval that the Prometheus will scrape for metrics.

</td>
<td>string</td>
<td>

```yaml
10s
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.scrapeTimeout</td>
<td>

The timeout on each metric probe request.

</td>
<td>string</td>
<td>

```yaml
5s
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.labels</td>
<td>

Additional labels to give the ServiceMonitor resource.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>app.readinessProbe.port</td>
<td>

Container port to expose istio-csr HTTP readiness probe on default network interface.

</td>
<td>number</td>
<td>

```yaml
6060
```

</td>
</tr>
<tr>

<td>app.readinessProbe.path</td>
<td>

Path to expose istio-csr HTTP readiness probe on default network interface.

</td>
<td>string</td>
<td>

```yaml
/readyz
```

</td>
</tr>
<tr>

<td>app.certmanager.namespace</td>
<td>

Namespace to create CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs.

</td>
<td>string</td>
<td>

```yaml
istio-system
```

</td>
</tr>
<tr>

<td>app.certmanager.preserveCertificateRequests</td>
<td>

Don't delete created CertificateRequests once they have been signed. WARNING: do not enable this option in production, or environments with any non-trivial number of workloads for an extended period of time. Doing so will balloon the resource consumption of both ETCD and the API server, leading to errors and slow down. This option is intended for debugging purposes only, for limited periods of time.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>app.certmanager.additionalAnnotations</td>
<td>

Additional annotations to include on certificate requests.  
Takes key/value pairs in the format:

```yaml
additionalAnnotations:
  - name: custom.cert-manager.io/policy-name
    value: istio-csr
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>app.certmanager.issuer.group</td>
<td>

Issuer name set on created CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs.

</td>
<td>string</td>
<td>

```yaml
istio-ca
```

</td>
</tr>
<tr>

<td>app.certmanager.issuer.group</td>
<td>

Issuer kind set on created CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs.

</td>
<td>string</td>
<td>

```yaml
Issuer
```

</td>
</tr>
<tr>

<td>app.certmanager.issuer.group</td>
<td>

Issuer group name set on created CertificateRequests for both istio-csr's serving certificate and incoming gRPC CSRs.

</td>
<td>string</td>
<td>

```yaml
cert-manager.io
```

</td>
</tr>
<tr>

<td>app.tls.trustDomain</td>
<td>

The Istio cluster's trust domain.

</td>
<td>string</td>
<td>

```yaml
cluster.local
```

</td>
</tr>
<tr>

<td>app.tls.rootCAFile</td>
<td>

An optional file location to a PEM encoded root CA that the root CA. ConfigMap in all namespaces will be populated with. If empty, the CA returned from cert-manager for the serving certificate will be used.

</td>
<td>unknown</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>app.tls.certificateDNSNames[0]</td>
<td>

</td>
<td>string</td>
<td>

```yaml
cert-manager-istio-csr.cert-manager.svc
```

</td>
</tr>
<tr>

<td>app.tls.certificateDuration</td>
<td>

Requested duration of gRPC serving certificate. Will be automatically renewed.  
Based on NIST 800-204A recommendations (SM-DR13).  
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf

</td>
<td>string</td>
<td>

```yaml
1h
```

</td>
</tr>
<tr>

<td>app.tls.istiodCertificateDuration</td>
<td>

Requested duration of istio's Certificate. Will be automatically renewed.  
Based on NIST 800-204A recommendations (SM-DR13).  
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf. Warning: cert-manager does not allow a duration on Certificates less than 1 hour.

</td>
<td>string</td>
<td>

```yaml
1h
```

</td>
</tr>
<tr>

<td>app.tls.istiodCertificateRenewBefore</td>
<td>

</td>
<td>string</td>
<td>

```yaml
30m
```

</td>
</tr>
<tr>

<td>app.tls.istiodCertificateEnable</td>
<td>

Create the default certificate as part of install.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>app.tls.istiodPrivateKeySize</td>
<td>

Number of bits to use for istiod-tls RSAKey

</td>
<td>number</td>
<td>

```yaml
2048
```

</td>
</tr>
<tr>

<td>app.server.clusterID</td>
<td>

The istio cluster ID to verify incoming CSRs.

</td>
<td>string</td>
<td>

```yaml
Kubernetes
```

</td>
</tr>
<tr>

<td>app.server.maxCertificateDuration</td>
<td>

Maximum validity duration that can be requested for a certificate. istio-csr will request a duration of the smaller of this value, and that of the incoming gRPC CSR.  
Based on NIST 800-204A recommendations (SM-DR13).  
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf

</td>
<td>string</td>
<td>

```yaml
1h
```

</td>
</tr>
<tr>

<td>app.server.serving.signatureAlgorithm</td>
<td>

Container address to serve istio-csr gRPC service.

</td>
<td>string</td>
<td>

```yaml
0.0.0.0
```

</td>
</tr>
<tr>

<td>app.server.serving.signatureAlgorithm</td>
<td>

Container port to serve istio-csr gRPC service.

</td>
<td>number</td>
<td>

```yaml
6443
```

</td>
</tr>
<tr>

<td>app.server.serving.signatureAlgorithm</td>
<td>

Number of bits to use for the server's serving certificate (RSAKeySize).

</td>
<td>number</td>
<td>

```yaml
2048
```

</td>
</tr>
<tr>

<td>app.server.serving.signatureAlgorithm</td>
<td>

The type of signature algorithm to use when generating private keys. Currently only RSA and ECDSA are supported. By default RSA is used.

</td>
<td>string</td>
<td>

```yaml
RSA
```

</td>
</tr>
<tr>

<td>app.istio.revisions[0]</td>
<td>

</td>
<td>string</td>
<td>

```yaml
default
```

</td>
</tr>
<tr>

<td>app.istio.namespace</td>
<td>

The namespace where the istio control-plane is running.

</td>
<td>string</td>
<td>

```yaml
istio-system
```

</td>
</tr>
<tr>

<td>app.controller.leaderElectionNamespace</td>
<td>

</td>
<td>string</td>
<td>

```yaml
istio-system
```

</td>
</tr>
<tr>

<td>app.controller.configmapNamespaceSelector</td>
<td>

If set, limit where istio-csr creates configmaps with root ca certificates. If unset, configmap created in ALL namespaces.  
Example: maistra.io/member-of=istio-system


</td>
<td>string</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>volumes</td>
<td>

Optional extra volumes. Useful for mounting custom root CAs  
  
For example:

```yaml
volumes:
- name: root-ca
  secret:
    secretName: root-cert
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>volumeMounts</td>
<td>

Optional extra volume mounts. Useful for mounting custom root CAs  
  
For example:

```yaml
volumeMounts:
- name: root-ca
  mountPath: /etc/tls
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>resources</td>
<td>

Kubernetes pod resources  
ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/  
  
For example:

```yaml
resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>affinity</td>
<td>

Expects input structure as per specification https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.11/#affinity-v1-core  
  
For example:

```yaml
affinity:
  nodeAffinity:
   requiredDuringSchedulingIgnoredDuringExecution:
     nodeSelectorTerms:
     - matchExpressions:
       - key: foo.bar.com/role
         operator: In
         values:
         - master
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>tolerations</td>
<td>

Expects input structure as per specification https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.11/#toleration-v1-core  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>nodeSelector</td>
<td>

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
</table>

<!-- /AUTO-GENERATED -->