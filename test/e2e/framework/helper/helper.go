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

package helper

import (
	"context"
	"fmt"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmversioned "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

type Helper struct {
	cmclient   cmversioned.Interface
	kubeclient kubernetes.Interface
}

func NewHelper(cmclient cmversioned.Interface, kubeclient kubernetes.Interface) *Helper {
	return &Helper{
		cmclient:   cmclient,
		kubeclient: kubeclient,
	}
}

// WaitForCertificateReady waits for the certificate resource to enter a Ready
// state.
func (h *Helper) WaitForCertificateReady(ctx context.Context, ns, name string, timeout time.Duration) (*cmapi.Certificate, error) {
	var certificate *cmapi.Certificate

	err := wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		certificate, err = h.cmclient.CertmanagerV1().Certificates(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error getting Certificate %s: %v", name, err)
		}
		isReady := apiutil.CertificateHasCondition(certificate, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionTrue,
		})
		if !isReady {
			return false, nil
		}
		return true, nil
	})

	// return certificate even when error to use for debugging
	return certificate, err
}

const (
	pollInterval  = time.Second
	pollImmediate = true
)

// WaitForLabelledPodsReady waits until at least one pod matching the given label selector is ready in the given namespace
func (h *Helper) WaitForLabelledPodsReady(ctx context.Context, ns string, labelSelector string, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, pollInterval, timeout, pollImmediate, func(ctx context.Context) (bool, error) {
		podsList, err := h.kubeclient.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		if err != nil {
			return false, err
		}

		// if there's no pods there yet, assume some will be created and continue
		if len(podsList.Items) == 0 {
			return false, nil
		}

		allReady := true

		for _, podFromList := range podsList.Items {
			pod, err := h.kubeclient.CoreV1().Pods(ns).Get(ctx, podFromList.Name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Pod %q: %v", podFromList.Name, err)
			}

			for _, c := range pod.Status.Conditions {
				if c.Type == corev1.PodReady {
					if c.Status != corev1.ConditionTrue {
						allReady = false
					}
				}
			}
		}

		return allReady, nil
	})
}
