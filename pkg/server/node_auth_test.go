/*
Copyright 2021 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"fmt"
	"testing"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/security"
	testUtil "istio.io/istio/pkg/test"
	"istio.io/istio/pkg/util/sets"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// See original code: https://github.com/istio/istio/blob/1.22.3/security/pkg/server/ca/node_auth_test.go
// See license of original code: https://github.com/istio/istio/blob/1.22.3/LICENSE
func TestAuthImpersonation(t *testing.T) {
	allowZtunnel := map[types.NamespacedName]struct{}{
		{Name: "ztunnel", Namespace: "istio-system"}: {},
	}
	ztunnelCaller := security.KubernetesInfo{
		PodName:           "ztunnel-a",
		PodNamespace:      "istio-system",
		PodUID:            "12345",
		PodServiceAccount: "ztunnel",
	}
	ztunnelPod := pod{
		name:      ztunnelCaller.PodName,
		namespace: ztunnelCaller.PodNamespace,
		account:   ztunnelCaller.PodServiceAccount,
		uid:       ztunnelCaller.PodUID,
		node:      "zt-node",
	}
	podSameNode := pod{
		name:      "pod-a",
		namespace: "ns-a",
		account:   "sa-a",
		uid:       "1",
		node:      "zt-node",
	}
	podOtherNode := pod{
		name:      "pod-b",
		namespace: podSameNode.namespace,
		account:   podSameNode.account,
		uid:       "2",
		node:      "other-node",
	}
	tests := map[string]struct {
		caller                  security.KubernetesInfo
		trustedNodeAccounts     sets.Set[types.NamespacedName]
		pods                    []pod
		requestedIdentityString string
		expErr                  error
	}{
		"if caller is trusted, and requested identity on same node, return nil": {
			caller:                  ztunnelCaller,
			trustedNodeAccounts:     allowZtunnel,
			pods:                    []pod{ztunnelPod, podSameNode},
			requestedIdentityString: podSameNode.Identity(),
			expErr:                  nil,
		},
		"if caller is trusted, and requested identity on same node with other nodes, return nil": {
			caller:                  ztunnelCaller,
			trustedNodeAccounts:     allowZtunnel,
			pods:                    []pod{ztunnelPod, podSameNode, podOtherNode},
			requestedIdentityString: podSameNode.Identity(),
			expErr:                  nil,
		},
		"if caller is not trusted, return error": {
			caller:                  ztunnelCaller,
			trustedNodeAccounts:     map[types.NamespacedName]struct{}{},
			pods:                    []pod{ztunnelPod, podSameNode},
			requestedIdentityString: podSameNode.Identity(),
			expErr:                  fmt.Errorf("caller (%v) is not allowed to impersonate", ztunnelCaller),
		},
		"if caller is trusted, but requested identity is not valid, return error": {
			caller:                  ztunnelCaller,
			trustedNodeAccounts:     allowZtunnel,
			pods:                    []pod{ztunnelPod, podSameNode},
			requestedIdentityString: "spiffe://invalid",
			expErr:                  fmt.Errorf("identity is not a spiffe format"),
		},
		"if caller is trusted, but requested identity not on same node, return error": {
			caller:                  ztunnelCaller,
			trustedNodeAccounts:     allowZtunnel,
			pods:                    []pod{ztunnelPod, podOtherNode},
			requestedIdentityString: podOtherNode.Identity(),
			expErr:                  fmt.Errorf("no instances of \"%s/%s\" found on node %q", podOtherNode.namespace, podOtherNode.account, ztunnelPod.node),
		},
		"if caller is trusted, but caller pod not found, return error": {
			caller:                  ztunnelCaller,
			trustedNodeAccounts:     allowZtunnel,
			pods:                    []pod{podSameNode},
			requestedIdentityString: podSameNode.Identity(),
			expErr:                  fmt.Errorf("pod %v/%v not found", ztunnelCaller.PodNamespace, ztunnelCaller.PodName),
		},
		"if caller is trusted, but caller pod UID does not match": {
			caller: security.KubernetesInfo{
				PodName:           "ztunnel-a",
				PodNamespace:      "istio-system",
				PodUID:            podSameNode.uid,
				PodServiceAccount: "ztunnel",
			},
			trustedNodeAccounts:     allowZtunnel,
			pods:                    []pod{ztunnelPod, podSameNode},
			requestedIdentityString: podSameNode.Identity(),
			expErr:                  fmt.Errorf("pod found, but UID does not match: %v vs %v", ztunnelCaller.PodUID, podSameNode.uid),
		},
		"if caller is trusted, but caller service account does not match": {
			caller:              ztunnelCaller,
			trustedNodeAccounts: allowZtunnel,
			pods: []pod{func(p pod) pod {
				p.account = podSameNode.account
				return p
			}(ztunnelPod)},
			requestedIdentityString: podSameNode.Identity(),
			expErr:                  fmt.Errorf("pod found, but ServiceAccount does not match: %v vs %v", podSameNode.account, ztunnelCaller.PodServiceAccount),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var pods []runtime.Object
			for _, p := range test.pods {
				pods = append(pods, &v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      p.name,
						Namespace: p.namespace,
						UID:       types.UID(p.uid),
					},
					Spec: v1.PodSpec{
						ServiceAccountName: p.account,
						NodeName:           p.node,
					},
				})
			}
			c := kube.NewFakeClient(pods...)
			na := NewClusterNodeAuthorizer(c, test.trustedNodeAccounts)
			c.RunAndWait(testUtil.NewStop(t))
			kube.WaitForCacheSync("test", testUtil.NewStop(t), na.pods.HasSynced)

			err := na.authenticateImpersonation(test.caller, test.requestedIdentityString)

			errS, _ := status.FromError(err)
			expErrS, _ := status.FromError(test.expErr)

			if !proto.Equal(errS.Proto(), expErrS.Proto()) {
				t.Errorf("unexpected error, exp=%v got=%v", test.expErr, err)
			}
		})
	}
}
