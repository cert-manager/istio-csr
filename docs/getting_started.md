# Getting Started With istio-csr

This guide will run through installing and using istio-csr from scratch. We'll use [kind](https://kind.sigs.k8s.io/) to create a new cluster locally in Docker, but this guide should work on any cluster as long as the relevant Istio [Platform Setup](https://istio.io/latest/docs/setup/platform-setup/) has been performed.

Note that if you're following the Platform Setup guide for OpenShift, do not run the `istioctl install` command listed in that guide; we'll run our own command later.

## Initial Setup

You'll need the following tools installed on your machine:

- [istioctl](https://github.com/istio/istio/releases/latest)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) and [docker](https://docs.docker.com/get-docker/) (if you're using kind)
- [helm](https://helm.sh/docs/intro/install/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
- [jq](https://stedolan.github.io/jq/download/)

In addition, Istio must not already be installed in your cluster. Installing istio-csr _after_ Istio is not supported.

## Creating the Cluster and Installing cert-manager

Kind will automatically set up kubectl to point to the newly created cluster.

We install cert-manager [using helm](https://cert-manager.io/docs/installation/helm/) here, but if you've got a preferred method you can install in any way.

```console
kind create cluster --image=docker.io/kindest/node:v1.22.4

# Helm setup
helm repo add jetstack https://charts.jetstack.io
helm repo update

# install cert-manager CRDs
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.6.1/cert-manager.crds.yaml

# install cert-manager; this might take a little time
helm install cert-manager jetstack/cert-manager \
	--namespace cert-manager \
	--create-namespace \
	--version v1.6.1

# We need this namespace to exist since our cert will be placed there
kubectl create namespace istio-system
```

## Create a cert-manager Issuer and Issuing Certificate

An Issuer tells cert-manager how to issue certificates; we'll create a self-signed root CA in our cluster because it's really simple to configure.

The approach of using a locally generated root certificate would work in a production deployment too, but there are also several [other issuers](https://cert-manager.io/docs/configuration/) in cert-manager which could be used. Note that the ACME issuer **will not work**, since it can't add the required fields to issued certificates.

There are also some comments on the [example-issuer](https://github.com/cert-manager/istio-csr/blob/main/docs/example-issuer.yaml) providing a little more detail. Note also that this guide only uses `Issuer`s and not `ClusterIssuer`s - using a `ClusterIssuer` isn't a drop-in replacement, and in any case we recommend that production deployments use Issuers for easier access controls and scoping.

```console
kubectl apply -f https://raw.githubusercontent.com/cert-manager/istio-csr/main/docs/example-issuer.yaml
```

## Export the Root CA to a Local File

While it's possible to configure Istio such that it can automatically "discover" the root CA, this can be dangerous in
some specific scenarios involving other security holes, enabling [signer hijacking attacks](https://github.com/cert-manager/istio-csr/issues/103#issuecomment-923882792).

As such, we'll export our Root CA and configure Istio later using that static cert.

```console
# Export our cert from the secret it's stored in, and base64 decode to get the PEM data.
kubectl get -n istio-system secret istio-ca -ogo-template='{{index .data "tls.crt"}}' | base64 -d > ca.pem

# Out of interest, we can check out what our CA looks like
openssl x509 -in ca.pem -noout -text

# Add our CA to a secret
kubectl create secret generic -n cert-manager istio-root-ca --from-file=ca.pem=ca.pem
```

## Installing istio-csr

istio-csr is best installed via Helm, and it should be simple and quick to install. There
are a bunch of other configuration options for the helm chart, which you can check out [here](https://github.com/cert-manager/istio-csr/blob/main/deploy/charts/istio-csr/README.md).

```console
helm repo add jetstack https://charts.jetstack.io
helm repo update

# We set a few helm template values so we can point at our static root CA
helm install -n cert-manager cert-manager-istio-csr jetstack/cert-manager-istio-csr \
	--set "app.tls.rootCAFile=/var/run/secrets/istio-csr/ca.pem" \
	--set "volumeMounts[0].name=root-ca" \
	--set "volumeMounts[0].mountPath=/var/run/secrets/istio-csr" \
	--set "volumes[0].name=root-ca" \
	--set "volumes[0].secret.secretName=istio-root-ca"

# Check to see that the istio-csr pod is running and ready
kubectl get pods -n cert-manager
NAME                                       READY   STATUS    RESTARTS   AGE
cert-manager-aaaaaaaaaa-11111              1/1     Running   0          9m46s
cert-manager-cainjector-aaaaaaaaaa-22222   1/1     Running   0          9m46s
cert-manager-istio-csr-bbbbbbbbbb-00000    1/1     Running   0          63s
cert-manager-webhook-aaaaaaaaa-33333       1/1     Running   0          9m46s
```

## Installing Istio

If you're not running on kind, you may need to do some additional [setup tasks](https://istio.io/latest/docs/setup/platform-setup/) before installing Istio.

We use the `istioctl` CLI to install Istio, configured using a custom IstioOperator manifest.

The custom manifest does the following:

- Disables the CA server in istiod,
- Ensures that Istio workloads request certificates from istio-csr,
- Ensures that the istiod certificates and keys are mounted from the Certificate created when installing istio-csr.

First we download our demo manifest and then we apply it.

```console
curl -sSL https://raw.githubusercontent.com/cert-manager/istio-csr/main/docs/istio-config-getting-started.yaml > istio-install-config.yaml
```

You may wish to inspect and tweak `istio-install-config.yaml` if you know what you're doing,
but this manifest should work for example purposes as-is.

If you set a custom `app.tls.trustDomain` when installing istio-csr via helm earlier, you'll need to ensure that
value is repeated in `istio-install-config.yaml`.

This final command will install Istio; the exact command you need might vary on different platforms,
and will certainly vary on OpenShift.

```console
# This takes a little time to complete
istioctl install -f istio-install-config.yaml

# If you're on OpenShift, you need a different profile:
# istioctl install --set profile=openshift -f istio-install-config.yaml
```

## Validating Install

The following steps are option but can be followed to validate everything is hooked correctly:

1. Deploy a sample application & watch for `certificaterequests.cert-manager.io` resources
2. Verify `cert-manager` logs for new `certificaterequests` and responses
3. Verify the CA Endpoint being used in a `istio-proxy` sidecar container
4. Using `istioctl` to fetch the certificate info for the `istio-proxy` container

To see this all in action, lets deploy a very simple sample application from the
[istio samples](https://github.com/istio/istio/tree/master/samples/httpbin).

First set some environment variables whose values could be changed if needed:

```shell
# Set namespace for sample application
export NAMESPACE=default
# Set env var for the value of the app label in manifests
export APP=httpbin
# Grab the installed version of istio
export ISTIO_VERSION=$(istioctl version -o json | jq -r '.meshVersion[0].Info.version')
```

We use the `default` namespace for simplicity, so let's label the namespace for istio injection:

```shell
kubectl label namespace $NAMESPACE istio-injection=enabled --overwrite
```

In a separate terminal you should now follow the logs for `cert-manager`:

```shell
kubectl logs -n cert-manager $(kubectl get pods -n cert-manager -o jsonpath='{.items..metadata.name}' --selector app=cert-manager) --since 2m -f
```

In another separate terminal, lets watch the `istio-system` namespace for `certificaterequests`:

```shell
kubectl get certificaterequests.cert-manager.io -n istio-system -w
```

Now deploy the sample application `httpbin` in the labeled namespace. Note the use of a
variable to match the manifest version to your installed istio version:

```shell
kubectl apply -n $NAMESPACE -f https://raw.githubusercontent.com/istio/istio/$ISTIO_VERSION/samples/httpbin/httpbin.yaml
```

You should see something similar to the output here for `certificaterequests`:

```
NAME             APPROVED   DENIED   READY   ISSUER       REQUESTOR                                         AGE
istio-ca-74bnl   True                True    selfsigned   system:serviceaccount:cert-manager:cert-manager   2d2h
istiod-w9zh6     True                True    istio-ca     system:serviceaccount:cert-manager:cert-manager   27m
istio-csr-8ddcs                               istio-ca     system:serviceaccount:cert-manager:cert-manager-istio-csr   0s
istio-csr-8ddcs   True                        istio-ca     system:serviceaccount:cert-manager:cert-manager-istio-csr   0s
istio-csr-8ddcs   True                True    istio-ca     system:serviceaccount:cert-manager:cert-manager-istio-csr   0s
istio-csr-8ddcs   True                True    istio-ca     system:serviceaccount:cert-manager:cert-manager-istio-csr   0s
```

The key request being `istio-csr-8ddcs` in our example output. You should then check your
`cert-manager` log output for two log lines with this request being "Approved" and "Ready":

```
I0113 16:51:59.186482       1 conditions.go:261] Setting lastTransitionTime for CertificateRequest "istio-csr-8ddcs" condition "Approved" to 2022-01-13 16:51:59.186455713 +0000 UTC m=+3507.098466775
I0113 16:51:59.258876       1 conditions.go:261] Setting lastTransitionTime for CertificateRequest "istio-csr-8ddcs" condition "Ready" to 2022-01-13 16:51:59.258837897 +0000 UTC m=+3507.170859959
```

You should now see the application is running with both the application container and the sidecar:

```shell
~ kubectl get pods -n $NAMESPACE
NAME                       READY   STATUS    RESTARTS   AGE
httpbin-74fb669cc6-559cg   2/2     Running   0           4m
```

To validate that the `istio-proxy` sidecar container has requested the certifiate from the correct
service, check the container logs:

```shell
kubectl logs $(kubectl get pod -n $NAMESPACE -o jsonpath="{.items...metadata.name}" --selector app=$APP) -c istio-proxy
```

You should see some early logs similar to this example:

```
2022-01-13T16:51:58.495493Z	info	CA Endpoint cert-manager-istio-csr.cert-manager.svc:443, provider Citadel
2022-01-13T16:51:58.495817Z	info	Using CA cert-manager-istio-csr.cert-manager.svc:443 cert with certs: var/run/secrets/istio/root-cert.pem
2022-01-13T16:51:58.495941Z	info	citadelclient	Citadel client using custom root cert: cert-manager-istio-csr.cert-manager.svc:443
```

Finally we can inspect the certificate being used in memory by Envoy. This one liner should return you the certificate being used:

```shell
istioctl proxy-config secret $(kubectl get pods -n $NAMESPACE -o jsonpath='{.items..metadata.name}' --selector app=$APP) -o json | jq -r '.dynamicActiveSecrets[0].secret.tlsCertificate.certificateChain.inlineBytes' | base64 --decode | openssl x509 -text -noout
```

In particular look for the following sections:

```
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=cert-manager, O=cluster.local, CN=istio-ca
        Validity
            Not Before: Jan 13 16:51:59 2022 GMT
            Not After : Jan 13 17:51:59 2022 GMT
...
            X509v3 Subject Alternative Name:
                URI:spiffe://cluster.local/ns/default/sa/httpbin
```

You should see the relevant Trust Domain inside the Issuer. In the default case, it should be:
`cluster.local` as above. Note that the SPIFFE URI may be different if you used a different
namespace or application.

## Clean up

Assuming your running inside kind, you can simply remove the cluster:

```shell
kind delete cluster kind
```
