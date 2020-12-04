#!/bin/sh

KUBECTL_BIN="${KUBECTL_BIN:-./bin/kubectl}"
KIND_BIN="${KIND_BIN:-./bin/kind}"
KIND_IMAGE="${KIND_IMAGE:-kindest/node:v$1}"

docker stop kind-registry

set -o errexit

$KIND_BIN delete cluster --name istio-demo

# create registry container unless it already exists
reg_name='kind-registry'
reg_port='5000'
running="$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"
if [ "${running}" != 'true' ]; then
  docker run \
    -d -p "${reg_port}:5000" --name "${reg_name}" --rm \
    registry:2
fi

# create a cluster with the local registry enabled in containerd
cat <<EOF | $KIND_BIN create cluster --image $KIND_IMAGE --name istio-demo --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30443
    hostPort: 30443
    listenAddress: "0.0.0.0"
    protocol: tcp
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:${reg_port}"]
kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        service-account-signing-key-file: /etc/kubernetes/pki/sa.key
        service-account-key-file: /etc/kubernetes/pki/sa.pub
        service-account-issuer: api
        service-account-api-audiences: api,istio-ca,factors
EOF

# connect the registry to the cluster network
docker network connect "kind" "${reg_name}"

# tell https://tilt.dev to use the registry
# https://docs.tilt.dev/choosing_clusters.html#discovering-the-registry
for node in $($KIND_BIN get nodes); do
  $KUBECTL_BIN annotate node "${node}" "kind.x-k8s.io/registry=localhost:${reg_port}";
done
