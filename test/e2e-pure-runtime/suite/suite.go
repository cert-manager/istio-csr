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

package suite

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmutil "github.com/cert-manager/cert-manager/pkg/util/pki"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/istio-csr/test/e2e/framework"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CasesDescribe("runtime configuration", func() {
	f := framework.NewDefaultFramework("runtime-configuration")

	var (
		namespaceName = "pure-runtimeconfig-ns"

		ctx = context.Background()
	)

	JustBeforeEach(func() {
		_, err := f.KubeClientSet.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespaceName,
				Labels: map[string]string{
					"istio-injection": "enabled",
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("creating second issuer")
		err = kubectl(f, "apply", "-f", "./manifests/issuer.yaml")
		Expect(err).NotTo(HaveOccurred())

		By(fmt.Sprintf("creating deployments in %s namespace", namespaceName))
		err = kubectl(f, "apply", "-n", namespaceName, "-f", "./manifests/sleep.yaml")
		Expect(err).NotTo(HaveOccurred())

		By(fmt.Sprintf("waiting for sleep pods in %s namespace to become ready", namespaceName))
		err = f.Helper().WaitForLabelledPodsReady(ctx, namespaceName, "app=sleep", time.Minute*10)
		if err != nil {
			err := kubectl(f, "describe", "-n", namespaceName, "pods")
			Expect(err).NotTo(HaveOccurred())
		}
	})

	JustAfterEach(func() {
		By(fmt.Sprintf("deleting %s namespace with deployments", namespaceName))

		err := f.KubeClientSet.CoreV1().Namespaces().Delete(ctx, namespaceName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should use the runtime configured issuer for running pods", func() {
		By("checking that already-created pods use the runtime configured issuer")
		pods, err := f.KubeClientSet.CoreV1().Pods(namespaceName).List(ctx, metav1.ListOptions{
			LabelSelector: "app=sleep",
		})
		Expect(err).NotTo(HaveOccurred())

		if len(pods.Items) != 1 {
			Expect(fmt.Errorf("expected single sleep pod in ns %q, got=%d", namespaceName, len(pods.Items))).NotTo(HaveOccurred())
		}

		istioCertChain, err := istioctlGetCert(f, pods.Items[0].Name, namespaceName)
		Expect(err).NotTo(HaveOccurred())

		Expect(istioCertChain).To(HaveLen(2), "expected exactly 2 certificates for the running sleep pod chain")

		Expect(istioCertChain[0].Issuer.OrganizationalUnit).To(BeEmpty(), "expected no OUs in running sleep pod's issuer")

		By("checking for dynamic istiod cert")
		istiodCertName := "istiod-dynamic"
		istiodCertNamespace := "istio-system"

		interval := 500 * time.Millisecond
		timeout := 1 * time.Minute
		pollImmediate := true

		var certificate *v1.Certificate

		pollErr := wait.PollUntilContextTimeout(ctx, interval, timeout, pollImmediate, func(ctx context.Context) (bool, error) {
			var err error
			certificate, err = f.CMClientSet.CertmanagerV1().Certificates(istiodCertNamespace).Get(ctx, istiodCertName, metav1.GetOptions{})
			if nil != err {
				certificate = nil
				return false, fmt.Errorf("error getting Certificate %v: %v", istiodCertName, err)
			}

			return apiutil.CertificateHasCondition(certificate, cmapi.CertificateCondition{
				Type:   cmapi.CertificateConditionReady,
				Status: cmmeta.ConditionTrue,
			}), nil
		})
		Expect(pollErr).NotTo(HaveOccurred())

		Expect(certificate.Spec.IssuerRef.Name).To(Equal("istio-ca"))
		Expect(certificate.Spec.IssuerRef.Kind).To(Equal("Issuer"))
		Expect(certificate.Spec.IssuerRef.Group).To(Equal("cert-manager.io"))
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

	// #nosec G204
	cmd := exec.Command(f.Config().IstioctlPath, "proxy-config", "secrets", "-n", namespaceName, podName, "-ojson")

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

		// We decode using DecodeX509CertificateSetBytes rather than a more specialised function
		// to ensure that we pick up everything that might appear in the output
		// Using a less-strict function is fine since this is a test.
		return cmutil.DecodeX509CertificateSetBytes(chainBytes)
	}

	return nil, fmt.Errorf("couldn't find cert secret for %s/%s", namespaceName, podName)
}
