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

package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/cert-manager/istio-csr/test/e2e/framework"
	cmclient "github.com/cert-manager/istio-csr/test/e2e/suite/internal/client"
	"github.com/cert-manager/istio-csr/test/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CasesDescribe("Request Authentication", func() {
	f := framework.NewDefaultFramework("request-authentication")

	var (
		rootCA    string
		saToken   string
		saName    string
		namespace string
	)

	JustBeforeEach(func() {
		By("creating test namespace with service account token")

		cm, err := f.KubeClientSet.CoreV1().ConfigMaps("istio-system").Get(context.TODO(), "istio-ca-root-cert", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		var ok bool
		rootCA, ok = cm.Data["root-cert.pem"]
		if !ok {
			Expect(cm, "epected CA root cert not present").NotTo(HaveOccurred())
		}

		ns, err := f.KubeClientSet.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cert-manager-istio-csr-e2e-",
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		namespace = ns.Name

		sa, err := f.KubeClientSet.CoreV1().ServiceAccounts(namespace).Create(context.TODO(), &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cert-manager-istio-csr-e2e-",
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		saName = sa.Name

		token, err := f.KubeClientSet.CoreV1().ServiceAccounts(namespace).CreateToken(context.TODO(), saName, &authv1.TokenRequest{
			Spec: authv1.TokenRequestSpec{
				Audiences:         []string{"istio-ca"},
				ExpirationSeconds: pointer.Int64(1200),
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		saToken = token.Status.Token
	})

	JustAfterEach(func() {
		By("removing test namespace with service account token")
		err := f.KubeClientSet.CoreV1().Namespaces().Delete(context.TODO(), namespace, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should reject a request with a bad service account token", func() {
		csr, err := gen.CSR(
			gen.SetCSRIdentities([]string{fmt.Sprintf("spiffe://foo.bar/ns/%s/sa/%s", namespace, saName)}),
		)
		Expect(err).NotTo(HaveOccurred())
		client, err := cmclient.NewCertManagerClient("localhost:30443", "bad token", true, []byte(rootCA), "")
		Expect(err).NotTo(HaveOccurred())
		_, err = client.CSRSign(csr, 100)
		Expect(err).To(HaveOccurred())
	})

	It("should reject a request with a bad csr", func() {
		client, err := cmclient.NewCertManagerClient("localhost:30443", saToken, true, []byte(rootCA), "")
		Expect(err).NotTo(HaveOccurred())
		_, err = client.CSRSign([]byte("bad csr"), 100)
		Expect(err).To(HaveOccurred())
	})

	It("should reject a request with dns", func() {
		id := fmt.Sprintf("spiffe://foo.bar/ns/%s/sa/%s", namespace, saName)
		csr, err := gen.CSR(
			gen.SetCSRIdentities([]string{id}),
			gen.SetCSRDNS([]string{"example.com", "jetstack.io"}),
		)
		Expect(err).NotTo(HaveOccurred())

		client, err := cmclient.NewCertManagerClient("localhost:30443", saToken, true, []byte(rootCA), "")
		Expect(err).NotTo(HaveOccurred())
		_, err = client.CSRSign(csr, 100)
		Expect(err).To(HaveOccurred())
	})

	It("should reject a request with ips", func() {
		id := fmt.Sprintf("spiffe://foo.bar/ns/%s/sa/%s", namespace, saName)
		csr, err := gen.CSR(
			gen.SetCSRIdentities([]string{id}),
			gen.SetCSRIPs([]string{"8.8.8.8"}),
		)
		Expect(err).NotTo(HaveOccurred())

		client, err := cmclient.NewCertManagerClient("localhost:30443", saToken, true, []byte(rootCA), "")
		Expect(err).NotTo(HaveOccurred())
		_, err = client.CSRSign(csr, 100)
		Expect(err).To(HaveOccurred())
	})

	It("should reject a request with emails", func() {
		id := fmt.Sprintf("spiffe://foo.bar/ns/%s/sa/%s", namespace, saName)
		csr, err := gen.CSR(
			gen.SetCSRIdentities([]string{id}),
			gen.SetCSREmails([]string{"joshua.vanleeuwen@jetstack.io"}),
		)
		Expect(err).NotTo(HaveOccurred())

		client, err := cmclient.NewCertManagerClient("localhost:30443", saToken, true, []byte(rootCA), "")
		Expect(err).NotTo(HaveOccurred())
		_, err = client.CSRSign(csr, 100)
		Expect(err).To(HaveOccurred())
	})

	It("should reject a request with emails", func() {
		id := fmt.Sprintf("spiffe://foo.bar/ns/%s/sa/%s", namespace, saName)
		csr, err := gen.CSR(
			gen.SetCSRIdentities([]string{id}),
			gen.SetCSREmails([]string{"joshua.vanleeuwen@jetstack.io"}),
		)
		Expect(err).NotTo(HaveOccurred())

		client, err := cmclient.NewCertManagerClient("localhost:30443", saToken, true, []byte(rootCA), "")
		Expect(err).NotTo(HaveOccurred())
		_, err = client.CSRSign(csr, 100)
		Expect(err).To(HaveOccurred())
	})

	It("should reject a request with wrong ids", func() {
		csr, err := gen.CSR(
			gen.SetCSRIdentities([]string{"spiffe://josh", "spiffe://bar"}),
		)
		Expect(err).NotTo(HaveOccurred())

		client, err := cmclient.NewCertManagerClient("localhost:30443", saToken, true, []byte(rootCA), "")
		Expect(err).NotTo(HaveOccurred())
		_, err = client.CSRSign(csr, 100)
		Expect(err).To(HaveOccurred())
	})

	It("should reject a request with more ids", func() {
		id := fmt.Sprintf("spiffe://foo.bar/ns/%s/sa/%s", namespace, saName)
		csr, err := gen.CSR(
			gen.SetCSRIdentities([]string{id, "spiffe://bar"}),
		)
		Expect(err).NotTo(HaveOccurred())

		client, err := cmclient.NewCertManagerClient("localhost:30443", saToken, true, []byte(rootCA), "")
		Expect(err).NotTo(HaveOccurred())
		_, err = client.CSRSign(csr, 100)
		Expect(err).To(HaveOccurred())
	})

	It("should correctly return a valid signed certificate on a correct request", func() {
		By("correctly request a valid certificate")

		id := fmt.Sprintf("spiffe://foo.bar/ns/%s/sa/%s", namespace, saName)
		csr, err := gen.CSR(
			gen.SetCSRIdentities([]string{id}),
		)
		Expect(err).NotTo(HaveOccurred())

		client, err := cmclient.NewCertManagerClient("localhost:30443", saToken, true, []byte(rootCA), "")
		Expect(err).NotTo(HaveOccurred())
		certs, err := client.CSRSign(csr, 100)
		Expect(err).NotTo(HaveOccurred())

		By("verify the returned root and leaf certificates are valid")

		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(rootCA))
		if !ok {
			Expect("failed to appent root certificate").NotTo(HaveOccurred())
		}

		for i, certPEM := range certs {
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				Expect("failed to parse certificate PEM").NotTo(HaveOccurred())
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				Expect(err).NotTo(HaveOccurred())
			}

			opts := x509.VerifyOptions{
				Roots:   roots,
				DNSName: "",
			}

			_, err = cert.Verify(opts)
			Expect(err).NotTo(HaveOccurred())

			// Root CA
			if i == len(certs)-1 {
				if len(cert.URIs) != 0 || !cert.IsCA {
					Expect(fmt.Errorf("%#+v: unexpected is CA", cert)).NotTo(HaveOccurred())
				}

				// Leaf
			} else {
				if len(cert.URIs) != 1 || cert.URIs[0].String() != id {
					Expect(fmt.Errorf("%#+v: unexpected id (%s)", cert.URIs, id)).NotTo(HaveOccurred())
				}
			}
		}

		By("ensuring CertificateRequest was created with correct annotation and request")

		crs, err := f.CMClientSet.CertmanagerV1().CertificateRequests("istio-system").List(context.TODO(), metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())

		var createdCR *cmapi.CertificateRequest
		for _, cr := range crs.Items {
			if val, ok := cr.Annotations["istio.cert-manager.io/identities"]; ok && val == id {
				cr := cr
				createdCR = &cr
				break
			}
		}

		if val, ok := createdCR.Annotations["custom.cert-manager.io/policy-name"]; !ok || val != "istio-csr" {
			Fail("Expected certificate-request-additional-annotation not present")
		}
		if createdCR == nil {
			Fail(fmt.Sprintf("did not find created CertificateRequest for identity %q", id))
		}
		if !bytes.Equal(createdCR.Spec.Request, csr) {
			Fail("request did not match that in CertificateRequest")
		}
		if createdCR.Spec.IsCA {
			Fail("unexpected IsCA on CertificateRequest")
		}
		if reflect.DeepEqual(createdCR.Spec.Duration, metav1.Duration{Duration: time.Second * 100}) {
			Fail(fmt.Sprintf(
				"duration did not match that expected in request, exp=%s got=%s",
				time.Second*100,
				createdCR.Spec.Duration,
			))
		}
	})
})
