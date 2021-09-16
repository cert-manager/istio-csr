#!/bin/bash

K8S_NAMESPACE="${K8S_NAMESPACE:-istio-system}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-1.4.0}"
ISTIO_AGENT_IMAGE="${CERT_MANAGER_ISTIO_AGENT_IMAGE:-quay.io/jetstack/cert-manager-istio-csr:canary}"
KUBECTL_BIN="${KUBECTL_BIN:-./bin/kubectl}"
HELM_BIN="${HELM_BIN:-./bin/helm}"
KIND_BIN="${KIND_BIN:-./bin/kind}"

echo ">> building istio-csr binary..."
GOARCH=$(go env GOARCH) GOOS=linux CGO_ENABLED=0 go build -o ./bin/istio-csr-linux ./cmd/.

echo ">> building docker image..."
docker build -t $ISTIO_AGENT_IMAGE .

echo ">> deleting any existing kind cluster..."
$KIND_BIN delete cluster --name istio-demo

echo ">> pre-creating 'kind' docker network to avoid networking issues in CI"
# When running in our CI environment the Docker network's subnet choice will cause issues with routing
# This works this around till we have a way to properly patch this.
docker network create --driver=bridge --subnet=192.168.0.0/16 --gateway 192.168.0.1 kind || true
# Sleep for 2s to avoid any races between docker's network subcommand and 'kind create'
sleep 2

echo ">> creating kind cluster..."
cat <<EOF | $KIND_BIN create cluster --name istio-demo --config=-
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30443
    hostPort: 30443
    listenAddress: "0.0.0.0"
    protocol: tcp
EOF

echo ">> loading docker image..."
$KIND_BIN load docker-image $ISTIO_AGENT_IMAGE --name istio-demo

echo ">> installing cert-manager"
$HELM_BIN repo add jetstack https://charts.jetstack.io --force-update
$HELM_BIN upgrade -i -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait --create-namespace --set global.logLevel=2

echo ">> creating cert-manager istio resources"
$KUBECTL_BIN create namespace $K8S_NAMESPACE
$KUBECTL_BIN apply -n $K8S_NAMESPACE -f ./hack/demo/cert-manager-bootstrap-resources.yaml

echo ">> installing cert-manager-istio-csr"
$HELM_BIN upgrade -i cert-manager-istio-csr ./deploy/charts/istio-csr -n cert-manager --values ./hack/demo/istio-csr-values.yaml --wait

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
