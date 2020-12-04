#!/bin/bash

K8S_NAMESPACE="${K8S_NAMESPACE:-istio-system}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-1.0.3}"
ISTIO_AGENT_IMAGE="${CERT_MANAGER_ISTIO_AGENT_IMAGE:-localhost:5000/cert-manager-istio-agent:v0.0.1-alpha.0}"
KUBECTL_BIN="${KUBECTL_BIN:-./bin/kubectl}"
HELM_BIN="${HELM_BIN:-./bin/helm}"

./hack/demo/kind-with-registry.sh $1

echo ">> docker build -t ${ISTIO_AGENT_IMAGE} ."
docker build -t ${ISTIO_AGENT_IMAGE} .

echo ">> docker push ${ISTIO_AGENT_IMAGE}"
docker push $ISTIO_AGENT_IMAGE

apply_cert-manager_bootstrap_manifests() {
  $KUBECTL_BIN apply -n $K8S_NAMESPACE -f ./hack/demo/cert-manager-bootstrap-resources.yaml
  return $?
}

echo ">> installing cert-manager"
$KUBECTL_BIN apply -f https://github.com/jetstack/cert-manager/releases/download/v$CERT_MANAGER_VERSION/cert-manager.yaml

$KUBECTL_BIN rollout status deploy -n cert-manager cert-manager
$KUBECTL_BIN rollout status deploy -n cert-manager cert-manager-cainjector
$KUBECTL_BIN rollout status deploy -n cert-manager cert-manager-webhook


echo ">> creating cert-manager istio resources"

$KUBECTL_BIN create namespace $K8S_NAMESPACE

max=15

for x in $(seq 1 $max); do
    apply_cert-manager_bootstrap_manifests
    res=$?

    if [ $res -eq 0 ]; then
        break
    fi

    echo ">> [${x}] cert-manager not ready" && sleep 5

    if [ x -eq 15 ]; then
        echo ">> Failed to deploy cert-manager and bootstrap manifests in time"
        exit 1
    fi
done

echo ">> installing cert-manager-istio-agent"

$HELM_BIN install cert-manager-istio-agent ./deploy/charts/istio-csr -n cert-manager --values ./hack/demo/values.yaml

echo ">> installing istio"

./bin/istioctl install -f ./hack/istio-config.yaml

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
