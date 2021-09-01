#!/bin/bash

K8S_NAMESPACE="${K8S_NAMESPACE:-istio-system}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-1.4.0}"
ISTIO_AGENT_IMAGE="${CERT_MANAGER_ISTIO_AGENT_IMAGE:-localhost:5000/cert-manager-istio-csr:v0.2.1}"
KUBECTL_BIN="${KUBECTL_BIN:-./bin/kubectl}"
HELM_BIN="${HELM_BIN:-./bin/helm}"
KIND_BIN="${KIND_BIN:-./bin/kind}"

echo ">> adding Jetstack Helm chart repository"
$HELM_BIN repo add jetstack https://charts.jetstack.io --force-update

./hack/demo/kind-with-registry.sh $1

echo ">> docker build -t ${ISTIO_AGENT_IMAGE} ."
docker build -t ${ISTIO_AGENT_IMAGE} .

echo ">> docker push ${ISTIO_AGENT_IMAGE}"
docker push $ISTIO_AGENT_IMAGE

echo ">> loading demo container images into kind"
IMAGES=("quay.io/joshvanl_jetstack/httpbin:latest" "quay.io/joshvanl_jetstack/curl")
IMAGES+=("gcr.io/istio-release/pilot:$2" "gcr.io/istio-release/proxyv2:$2")
for image in ${IMAGES[@]}; do
  docker pull $image
  $KIND_BIN load docker-image $image --name istio-demo
done

echo ">> installing cert-manager"
$HELM_BIN upgrade -i -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait --create-namespace --set global.logLevel=2

echo ">> creating cert-manager istio resources"
$KUBECTL_BIN create namespace $K8S_NAMESPACE
$KUBECTL_BIN apply -n $K8S_NAMESPACE -f ./hack/demo/cert-manager-bootstrap-resources.yaml

echo ">> installing cert-manager-istio-csr"
$HELM_BIN install cert-manager-istio-csr ./deploy/charts/istio-csr -n cert-manager --values ./hack/demo/istio-csr-values.yaml

echo ">> installing istio"

./bin/istioctl-$2 install -y -f ./hack/istio-config-$2.yaml

echo ">> enforcing mTLS everywhere"

$KUBECTL_BIN apply -n istio-system -f - <<EOF
apiVersion: "security.istio.io/v1beta1"
kind: "PeerAuthentication"
metadata:
  name: "default"
spec:
  mtls:
    mode: STRICT
EOF
