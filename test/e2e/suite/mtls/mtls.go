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

package mtls

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/istio-csr/test/e2e/framework"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CasesDescribe("mTLS correctness", func() {
	f := framework.NewDefaultFramework("mtls-correctness")

	var (
		namespaces = []struct {
			name   string
			inject bool
		}{
			{
				name:   "foo",
				inject: true,
			},
			{
				name:   "bar",
				inject: true,
			},
			{
				name:   "legacy",
				inject: false,
			},
		}

		ctx = context.Background()
	)

	JustBeforeEach(func() {
		By("creating foo, bar, and legacy namespaces with resources")

		for _, ns := range namespaces {
			By(fmt.Sprintf(
				"creating %s namespace with deployments, inject=%t",
				ns.name, ns.inject,
			))

			injectEnabled := "enabled"
			if !ns.inject {
				injectEnabled = "disabled"
			}

			_, err := f.KubeClientSet.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: ns.name,
					Labels: map[string]string{
						"istio-injection": injectEnabled,
					},
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			cmd := exec.Command(f.Config().KubectlPath, "apply", "-n"+ns.name, "-f", "./manifests/.")
			cmd.Stdout = GinkgoWriter
			cmd.Stderr = GinkgoWriter
			Expect(cmd.Run()).NotTo(HaveOccurred())
		}

		for _, ns := range namespaces {
			By(fmt.Sprintf("waiting for pods in %q namespace to become ready", ns.name))
			err := f.Helper().WaitForPodsReady(ns.name, time.Minute*10)
			if err != nil {
				cmd := exec.Command(f.Config().KubectlPath, "describe", "-n"+ns.name, "pods")
				cmd.Stdout = GinkgoWriter
				cmd.Stderr = GinkgoWriter
				Expect(cmd.Run()).NotTo(HaveOccurred())

				Expect(err).NotTo(HaveOccurred())
			}
		}
	})

	JustAfterEach(func() {
		By("deleting foo, bar, and legacy namespaces with resources")

		for _, ns := range namespaces {
			By(fmt.Sprintf(
				"deleting %s namespace with deployments, inject=%t",
				ns.name, ns.inject,
			))

			err := f.KubeClientSet.CoreV1().Namespaces().Delete(ctx, ns.name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("it should enforce mTLS, and fail for non-mTLS to mTLS", func() {
		for _, originNs := range namespaces {
			By(fmt.Sprintf(
				"checking mTLS for %s namespace, inject=%t",
				originNs.name, originNs.inject,
			))

			originPods, err := f.KubeClientSet.CoreV1().Pods(originNs.name).List(ctx, metav1.ListOptions{
				LabelSelector: "app=sleep",
			})
			Expect(err).NotTo(HaveOccurred())

			if len(originPods.Items) != 1 {
				Expect(fmt.Errorf("expected single sleep pod in ns %q, got=%d", originNs.name, len(originPods.Items))).NotTo(HaveOccurred())
			}

			for _, targetNs := range namespaces {
				buf := new(bytes.Buffer)

				cmd := exec.Command(f.Config().KubectlPath, "exec", "-n"+originNs.name, originPods.Items[0].Name, "-csleep", "--",
					"curl", fmt.Sprintf("http://httpbin.%s:8000/ip", targetNs.name), "-s", "-o", "/dev/null", "-w", "%{http_code}")
				cmd.Stdout = buf
				cmd.Stderr = GinkgoWriter
				cmd.Run()

				// if the origin pod has proxy, target pod has a proxy, we should expect 200
				// if the origin pod has proxy, target does not, we should expect 200
				// if the origin doesn't have proxy, target does, we should expect 000
				// if the origin doesn't have proxy, target doesn't, we should expect 200

				var badResult bool
				if !originNs.inject && targetNs.inject {
					badResult = buf.String() != "000"
				} else {
					badResult = buf.String() != "200"
				}

				if badResult {
					Expect(fmt.Errorf("origin namespace %q has inject=%t, target namespace %q has inject=%t, but got curl response=%s",
						originNs.name, originNs.inject, targetNs.name, targetNs.inject, buf.String(),
					)).NotTo(HaveOccurred())
				}
			}
		}
	})
})
