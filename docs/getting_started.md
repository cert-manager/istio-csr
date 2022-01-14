# Getting Started With istio-csr

This guide will run through installing and using istio-csr from scratch. We'll use [kind](https://kind.sigs.k8s.io/) to create a new cluster locally in Docker, but this guide should work on any cluster as long as the relevant Istio [Platform Setup](https://istio.io/latest/docs/setup/platform-setup/) has been performed.

Note that if you're following the Platform Setup guide for OpenShift, do not run the `istioctl install` command listed in that guide; we'll run our own command later.

## Initial Setup

You'll need the following tools installed on your machine:

- [istioctl](https://github.com/istio/istio/releases/latest)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) and [docker](https://docs.docker.com/get-docker/) (if you're using kind)
- [helm](https://helm.sh/docs/intro/install/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)

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
