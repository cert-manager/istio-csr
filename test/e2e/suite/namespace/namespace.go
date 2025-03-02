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

package namespace

import (
	"bytes"
	"context"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/istio-csr/test/e2e/framework"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CasesDescribe("CA Root Controller", func() {
	f := framework.NewDefaultFramework("ca-root-controller")

	var (
		testName    = "cert-manager-istio-csr-e2e-root-ca"
		cmNamespace = "istio-system"
		ctx         = context.Background()
		rootCA      []byte
	)

	JustBeforeEach(func() {
		By("collecting the current root CA which should be propagated")

		// Get root CA from a dummy Certificate using configured issuer
		cert := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testName,
				Namespace: cmNamespace,
			},
			Spec: cmapi.CertificateSpec{
				CommonName: testName,
				IssuerRef:  f.Config().IssuerRef,
				SecretName: testName,
			},
		}

		cert, err := f.CMClientSet.CertmanagerV1().Certificates(cmNamespace).Create(ctx, cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = f.Helper().WaitForCertificateReady(ctx, cmNamespace, cert.Name, time.Second*10)
		Expect(err).NotTo(HaveOccurred())

		certSecret, err := f.KubeClientSet.CoreV1().Secrets(cmNamespace).Get(ctx, testName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		rootCA = certSecret.Data[cmmeta.TLSCAKey]
		Expect(rootCA).NotTo(BeEmpty(), "failed to find root CA key in test certificate secret")
	})

	JustAfterEach(func() {
		By("remove existing test certificate")
		err := f.CMClientSet.CertmanagerV1().Certificates(cmNamespace).Delete(ctx, testName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("all namespaces should have valid configs in", func() {
		By("ensure all existing namespaces have the correct root CA")

		pollInterval := 1 * time.Second
		pollTimeout := 2 * time.Minute
		pollImmediate := true

		err := wait.PollUntilContextTimeout(ctx, pollInterval, pollTimeout, pollImmediate, func(ctx context.Context) (bool, error) {
			nss, err := f.KubeClientSet.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, err
			}

			for _, ns := range nss.Items {
				err = expectRootCAExists(ctx, f, ns.Name, rootCA)
				if err != nil {
					By(fmt.Sprintf("rootCA not yet propagated: %s", err))
					return false, nil
				}
			}

			return true, nil
		})

		Expect(err).NotTo(HaveOccurred())
	})

	It("should correctly update when a namespace updates and config map changes", func() {
		By("ensure a newly namespace is propagated")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cert-manager-istio-csr-e2e-",
			},
		}

		ns, err := f.KubeClientSet.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		defer func() {
			By("removing test namespace")
			Expect(f.KubeClientSet.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})).NotTo(HaveOccurred())
		}()

		Expect(expectRootCAExists(ctx, f, ns.Name, rootCA)).NotTo(HaveOccurred())

		By("if the config map contents is overridden, it should revert the changes")
		cm, err := f.KubeClientSet.CoreV1().ConfigMaps(ns.Name).Get(ctx, "istio-ca-root-cert", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		cm.Data[cmmeta.TLSCAKey] = "foo-bar"

		cm, err = f.KubeClientSet.CoreV1().ConfigMaps(ns.Name).Update(ctx, cm, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		Expect(expectRootCAExists(ctx, f, ns.Name, rootCA)).NotTo(HaveOccurred())

		By("if the config map contents is deleted, it should revert the changes")
		Eventually(func() error {
			cm, err = f.KubeClientSet.CoreV1().ConfigMaps(ns.Name).Get(ctx, "istio-ca-root-cert", metav1.GetOptions{})
			if err != nil {
				return err
			}

			delete(cm.Data, cmmeta.TLSCAKey)

			cm, err = f.KubeClientSet.CoreV1().ConfigMaps(ns.Name).Update(ctx, cm, metav1.UpdateOptions{})
			return err
		}).Should(Succeed())

		Expect(expectRootCAExists(ctx, f, ns.Name, rootCA)).NotTo(HaveOccurred())
	})
})

func expectRootCAExists(ctx context.Context, f *framework.Framework, ns string, rootCA []byte) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	for {
		cm, err := f.KubeClientSet.CoreV1().ConfigMaps(ns).Get(ctx, "istio-ca-root-cert", metav1.GetOptions{})

		if err == nil {
			if data, ok := cm.Data["root-cert.pem"]; !ok || !bytes.Equal([]byte(data), rootCA) {
				err = fmt.Errorf("%+#v: expected root CA not present in ConfigMap", cm)
			}
		}

		if err == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return err
		default:
			time.Sleep(time.Millisecond * 100)
			continue
		}
	}
}
