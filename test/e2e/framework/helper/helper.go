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
func (h *Helper) WaitForCertificateReady(ns, name string, timeout time.Duration) (*cmapi.Certificate, error) {
	var certificate *cmapi.Certificate

	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			certificate, err = h.cmclient.CertmanagerV1().Certificates(ns).Get(context.TODO(), name, metav1.GetOptions{})
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
		},
	)

	// return certificate even when error to use for debugging
	return certificate, err
}

// WaitForPodsReady waits for all pods in a namespace to become ready
func (h *Helper) WaitForPodsReady(ns string, timeout time.Duration) error {
	podsList, err := h.kubeclient.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, pod := range podsList.Items {
		err := wait.PollImmediate(time.Second, timeout,
			func() (bool, error) {
				var err error
				pod, err := h.kubeclient.CoreV1().Pods(ns).Get(context.TODO(), pod.Name, metav1.GetOptions{})
				if err != nil {
					return false, fmt.Errorf("error getting Pod %q: %v", pod.Name, err)
				}
				for _, c := range pod.Status.Conditions {
					if c.Type == corev1.PodReady {
						return c.Status == corev1.ConditionTrue, nil
					}
				}

				return false, nil
			},
		)

		if err != nil {
			return fmt.Errorf("failed to wait for pod %q to become ready: %s",
				pod.Name, err)
		}
	}

	return nil
}
