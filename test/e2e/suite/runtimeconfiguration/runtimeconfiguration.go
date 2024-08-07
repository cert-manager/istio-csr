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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/util/pki"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/istio-csr/test/e2e/framework"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CasesDescribe("runtime configuration", func() {
	f := framework.NewDefaultFramework("runtime-configuration")

	var (
		namespaceName = "runtimeconfig-ns"

		ctx = context.Background()

		injectLabel = func() map[string]string {
			if f.Config().AmbientEnabled {
				return map[string]string{
					"istio.io/dataplane-mode": "ambient",
				}
			} else {
				return map[string]string{
					"istio-injection": "enabled",
				}
			}
		}()
	)

	JustBeforeEach(func() {
		_, err := f.KubeClientSet.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   namespaceName,
				Labels: injectLabel,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("creating runtime configuration issuer")
		err = kubectl(f, "apply", "-f", "./runtimeconfig-manifests/issuers/.")
		Expect(err).NotTo(HaveOccurred())

		By("creating deployments in runtimeconfig namespace")
		err = kubectl(f, "apply", "-n", namespaceName, "-f", "./manifests/sleep.yaml")
		Expect(err).NotTo(HaveOccurred())

		By("waiting for sleep pods in runtimeconfig namespace to become ready")
		err = f.Helper().WaitForLabelledPodsReady(ctx, namespaceName, "app=sleep", time.Minute*10)
		if err != nil {
			err := kubectl(f, "describe", "-n", namespaceName, "pods")
			Expect(err).NotTo(HaveOccurred())
		}
	})

	JustAfterEach(func() {
		By("deleting runtimeconfig namespace with deployments")

		err := f.KubeClientSet.CoreV1().Namespaces().Delete(ctx, namespaceName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("it should use the runtime configured issuer", func() {
		//TODO: paulwilljones fix for Ambient
		if f.Config().AmbientEnabled {
			Skip("Skipping for Ambient")
		}
		By("creating runtime configuration configmap")
		err := kubectl(f, "apply", "-f", "./runtimeconfig-manifests/configmap/.")
		Expect(err).NotTo(HaveOccurred())

		defer func() {
			err := cleanupRuntimeConfigResources(f)
			Expect(err).NotTo(HaveOccurred())
		}()

		{
			By("checking that already-created pods use the old issuer")
			pods, err := f.KubeClientSet.CoreV1().Pods(namespaceName).List(ctx, metav1.ListOptions{
				LabelSelector: "app=sleep",
			})
			Expect(err).NotTo(HaveOccurred())

			if len(pods.Items) != 1 {
				Expect(fmt.Errorf("expected single sleep pod in ns %q, got=%d", namespaceName, len(pods.Items))).NotTo(HaveOccurred())
			}

			certsBefore, err := istioctlGetCert(f, pods.Items[0].Name, namespaceName)
			Expect(err).NotTo(HaveOccurred())

			Expect(certsBefore).To(HaveLen(2), "expected exactly 2 certificates for the running sleep pod chain")

			Expect(certsBefore[0].Issuer.OrganizationalUnit).To(BeEmpty(), "expected no OUs in running sleep pod's issuer")

			By("Deleting sleep pod to trigger re-issuance")
			err = kubectl(f, "delete", "-n", namespaceName, "pods", pods.Items[0].Name)
			Expect(err).NotTo(HaveOccurred())

		}

		err = f.Helper().WaitForLabelledPodsReady(ctx, namespaceName, "app=sleep", time.Minute*10)
		if err != nil {
			err := kubectl(f, "describe", "-n", namespaceName, "pods")
			Expect(err).NotTo(HaveOccurred())
		}

		{
			By("checking that the new sleep pod uses the runtime-configured issuer")
			pods, err := f.KubeClientSet.CoreV1().Pods(namespaceName).List(ctx, metav1.ListOptions{
				LabelSelector: "app=sleep",
			})
			Expect(err).NotTo(HaveOccurred())

			if len(pods.Items) != 1 {
				Expect(fmt.Errorf("expected single sleep pod in ns %q, got=%d", namespaceName, len(pods.Items))).NotTo(HaveOccurred())
			}

			certsAfter, err := istioctlGetCert(f, pods.Items[0].Name, namespaceName)
			Expect(err).NotTo(HaveOccurred())

			Expect(certsAfter).To(HaveLen(3), "expected exactly 3 certificates for the running sleep pod chain")

			Expect(certsAfter[0].Issuer.OrganizationalUnit).To(HaveLen(1), "expected one OU in running sleep pod's issuer")
			Expect(certsAfter[0].Issuer.OrganizationalUnit[0]).To(Equal("runtimeconfig"), "expected 'runtimeconfig' OU for issuer of workload identity")
		}
	})
})

// diveMap "dives" into a map, extracting another map from the given key and performing error checks
func diveMap(m map[string]any, key string) (map[string]any, error) {
	rawObject, exists := m[key]
	if !exists {
		return nil, fmt.Errorf("key %q not found in map", key)
	}

	innerMap, isMap := rawObject.(map[string]any)
	if !isMap {
		return nil, fmt.Errorf("key %q in map was not an object with string keys", key)
	}

	return innerMap, nil
}

func kubectl(f *framework.Framework, args ...string) error {
	stdout, err := kubectlWithOutput(f, args...)

	GinkgoWriter.Println(stdout)

	return err
}

func kubectlWithOutput(f *framework.Framework, args ...string) (string, error) {
	buf := &bytes.Buffer{}

	// #nosec G204
	cmd := exec.Command(f.Config().KubectlPath, args...)

	cmd.Stdout = buf
	cmd.Stderr = GinkgoWriter

	err := cmd.Run()

	return buf.String(), err
}

func cleanupRuntimeConfigResources(f *framework.Framework) error {
	var cleanupErrs []error

	err := kubectl(f, "delete", "-f", "./runtimeconfig-manifests/configmap/.")
	if err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}

	err = kubectl(f, "delete", "-f", "./runtimeconfig-manifests/issuers/.")
	if err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}

	return errors.Join(cleanupErrs...)
}

type IstioctlSecret struct {
	Name        string         `json:"name"`
	LastUpdated string         `json:"lastUpdated"`
	Secret      map[string]any `json:"secret"`
}

type IstioctlJSONWrapper struct {
	DynamicActiveSecrets []IstioctlSecret `json:"dynamicActiveSecrets"`
}

func istioctlGetCert(f *framework.Framework, podName string, namespaceName string) ([]*x509.Certificate, error) {
	buf := &bytes.Buffer{}

	//TODO: paulwilljones get certs from ztunnel
	cmd := func() *exec.Cmd {
		if f.Config().AmbientEnabled {
			// #nosec G204
			return exec.Command(f.Config().IstioctlPath, "experimental", "ztunnel-config", "certificates", "-n", namespaceName, "-ojson")
		} else {
			// #nosec G204
			return exec.Command(f.Config().IstioctlPath, "proxy-config", "secrets", "-n", namespaceName, podName, "-ojson")
		}
	}()

	cmd.Stdout = buf
	cmd.Stderr = GinkgoWriter

	err := cmd.Run()
	if err != nil {
		GinkgoWriter.Println(buf.String())
		return nil, err
	}

	jsonOutput := buf.Bytes()

	var wrapper IstioctlJSONWrapper

	err = json.Unmarshal(jsonOutput, &wrapper)
	if err != nil {
		return nil, err
	}

	if len(wrapper.DynamicActiveSecrets) == 0 {
		return nil, fmt.Errorf("fatal: got no secrets from istioctl")
	}

	for _, secret := range wrapper.DynamicActiveSecrets {
		if secret.Name != "default" {
			continue
		}

		tlsCertificateMap, err := diveMap(secret.Secret, "tlsCertificate")
		if err != nil {
			return nil, err
		}

		certificateChainMap, err := diveMap(tlsCertificateMap, "certificateChain")
		if err != nil {
			return nil, err
		}

		base64Raw, ok := certificateChainMap["inlineBytes"]
		if !ok {
			return nil, fmt.Errorf("failed to find inlineBytes key in certificateChain part of secret")
		}

		base64String, ok := base64Raw.(string)
		if !ok {
			return nil, fmt.Errorf("failed to convert inlineBytes to a string")
		}

		chainBytes, err := base64.StdEncoding.DecodeString(base64String)
		if err != nil {
			return nil, err
		}

		return cmutil.DecodeX509CertificateSetBytes(chainBytes)
	}

	return nil, fmt.Errorf("couldn't find cert secret for %s/%s", namespaceName, podName)
}
