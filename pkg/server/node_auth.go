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

	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/security/pkg/server/ca"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ClusterNodeAuthorizer is a component that implements a subset of Kubernetes Node Authorization
// (https://kubernetes.io/docs/reference/access-authn-authz/node/) for Istio CA within one cluster.
// Specifically, it validates that a node proxy which requests certificates for workloads on its
// own node is requesting valid identities which run on that node (rather than arbitrary ones).
// This implementation is based on Istio, but ensures the pod informer is synced before
// creating the index.
// (https://github.com/istio/istio/blob/1.22.1/security/pkg/server/ca/node_auth.go#L74)
// See license of original code: https://github.com/istio/istio/blob/1.22.3/LICENSE

type ClusterNodeAuthorizer struct {
	trustedNodeAccounts sets.Set[types.NamespacedName]
	pods                kclient.Client[*v1.Pod]
	nodeIndex           kclient.Index[ca.SaNode, *v1.Pod]
}

func NewClusterNodeAuthorizer(client kube.Client, trustedNodeAccounts sets.Set[types.NamespacedName]) *ClusterNodeAuthorizer {
	pods := kclient.NewFiltered[*v1.Pod](client, kclient.Filter{
		ObjectFilter:    client.ObjectFilter(),
		ObjectTransform: kube.StripPodUnusedFields,
	})

	stopCh := make(chan struct{})
	client.RunAndWait(stopCh)
	kube.WaitForCacheSync("nodeAuth", stopCh, pods.HasSynced)

	// Add an Index on the pods, storing the service account and node. This allows us to later efficiently query.
	index := kclient.CreateIndex[ca.SaNode, *v1.Pod](pods, "podSANode", func(pod *v1.Pod) []ca.SaNode {
		if len(pod.Spec.NodeName) == 0 {
			return nil
		}
		if len(pod.Spec.ServiceAccountName) == 0 {
			return nil
		}
		return []ca.SaNode{{
			ServiceAccount: types.NamespacedName{
				Namespace: pod.Namespace,
				Name:      pod.Spec.ServiceAccountName,
			},
			Node: pod.Spec.NodeName,
		}}
	})

	return &ClusterNodeAuthorizer{
		pods:                pods,
		nodeIndex:           index,
		trustedNodeAccounts: trustedNodeAccounts,
	}
}

// authenticateImpersonation will verify the caller is authorized to impersonate the requested identity
func (na *ClusterNodeAuthorizer) authenticateImpersonation(caller security.KubernetesInfo, requestedIdentityString string) error {
	callerSa := types.NamespacedName{
		Namespace: caller.PodNamespace,
		Name:      caller.PodServiceAccount,
	}

	// First, make sure the caller is allowed to impersonate, in general
	if _, f := na.trustedNodeAccounts[callerSa]; !f {
		return fmt.Errorf("caller (%v) is not allowed to impersonate", caller)
	}

	// Next, make sure the identity they want to impersonate is valid, in general
	requestedIdentity, err := spiffe.ParseIdentity(requestedIdentityString)
	if err != nil {
		return err
	}

	// Finally, we validate the requested identity is running on the same node the caller is on
	callerPod := na.pods.Get(caller.PodName, caller.PodNamespace)
	if callerPod == nil {
		return fmt.Errorf("pod %v/%v not found", caller.PodNamespace, caller.PodName)
	}
	// Make sure UID is still valid for our current state
	if callerPod.UID != types.UID(caller.PodUID) {
		// This would only happen if a pod is re-created with the same name, and the CSR client is not in sync on which is current;
		// this is fine and should be eventually consistent. Client is expected to retry in this case.
		return fmt.Errorf("pod found, but UID does not match: %v vs %v", callerPod.UID, caller.PodUID)
	}
	if callerPod.Spec.ServiceAccountName != caller.PodServiceAccount {
		// This should never happen, but just in case add an additional check
		return fmt.Errorf("pod found, but ServiceAccount does not match: %v vs %v", callerPod.Spec.ServiceAccountName, caller.PodServiceAccount)
	}
	// We want to find out if there is any pod running with the requested identity on the callers node.
	// The indexer (previously setup) creates a lookup table for a {Node, SA} pair, which we can lookup
	k := ca.SaNode{
		ServiceAccount: types.NamespacedName{Name: requestedIdentity.ServiceAccount, Namespace: requestedIdentity.Namespace},
		Node:           callerPod.Spec.NodeName,
	}
	// TODO: this is currently single cluster; we will need to take the cluster of the proxy into account
	// to support multi-cluster properly.
	res := na.nodeIndex.Lookup(k)
	// We don't care what pods are part of the index, only that there is at least one. If there is one,
	// it is appropriate for the caller to request this identity.
	if len(res) == 0 {
		return fmt.Errorf("no instances of %q found on node %q", k.ServiceAccount, k.Node)
	}
	log.Debugf("Node caller %v impersonated %v", caller, requestedIdentityString)
	return nil
}
