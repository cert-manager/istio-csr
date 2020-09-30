#!/bin/bash

K8S_NAMESPACE="${K8S_NAMESPACE:-istio-system}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-1.0.1}"

apply_cert-manager_bootstrap_manifests() {
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $K8S_NAMESPACE
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: selfsigned
  namespace: $K8S_NAMESPACE
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: istio-ca
  namespace: $K8S_NAMESPACE
spec:
  isCA: true
  duration: 2160h # 90d
  secretName: istio-ca
  commonName: istio-ca
  subject:
    organizations:
    - cluster.local
    - cert-manager
  issuerRef:
    name: selfsigned
    kind: Issuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: istio-ca
  namespace: $K8S_NAMESPACE
spec:
  ca:
    secretName: istio-ca
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: istiod
  namespace: $K8S_NAMESPACE
spec:
  isCA: false
  duration: 2160h # 90d
  secretName: istiod-tls
  dnsNames:
  - istiod.istio-system.svc
  uris:
    - spiffe://cluster.local/ns/istio-system/sa/istiod-service-account
  issuerRef:
    name: istio-ca
    kind: Issuer
    group: cert-manager.io
EOF

return $?
}

echo ">> installing cert-manager"
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v$CERT_MANAGER_VERSION/cert-manager.yaml

kubectl rollout status deploy -n cert-manager cert-manager
kubectl rollout status deploy -n cert-manager cert-manager-cainjector
kubectl rollout status deploy -n cert-manager cert-manager-webhook


echo ">> creating cert-manager istio resources"

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

sleep 30

echo ">> installing cert-manager-istio-agent"

kubectl apply -f ./deploy/yaml/deploy.yaml

echo ">> installing istio"

./demo/istioctl install -f ./demo/istio-config.yaml
