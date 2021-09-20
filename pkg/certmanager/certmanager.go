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

package certmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmversioned "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
)

const (
	identityAnnotation = "istio.cert-manager.io/identities"
)

type Options struct {
	// If PreserveCertificateRequests is true, requests will not be deleted after
	// they are signed.
	PreserveCertificateRequests bool

	// Namespace is the namespace that CertificateRequests will be created in.
	Namespace string

	// IssuerRef is used as the issuerRef on created CertificateRequests.
	IssuerRef cmmeta.ObjectReference
}

type Signer interface {
	// Sign will create a CertificateRequest based on the provided inputs. It will
	// wait for it to reach a terminal state, before optionally deleting it if
	// preserving CertificateRequests if turned off. Will return the certificate
	// bundle on successful signing.
	Sign(ctx context.Context, identities string, csrPEM []byte, duration time.Duration, usages []cmapi.KeyUsage) (Bundle, error)
}

// manager is used for signing CSRs via cert-manager. manager will create
// CertificateRequests and wait for them to be signed, before returning the
// result.
type manager struct {
	opts Options
	log  logr.Logger

	client cmclient.CertificateRequestInterface
}

// Bundle represents the `status.Certificate` and `status.CA` that is is
// populate on a CertificateRequest once it has been signed.
type Bundle struct {
	Certificate []byte
	CA          []byte
}

func New(log logr.Logger, restConfig *rest.Config, opts Options) (*manager, error) {
	client, err := cmversioned.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build cert-manager client: %s", err)
	}

	return &manager{
		log:    log.WithName("cert-manager"),
		client: client.CertmanagerV1().CertificateRequests(opts.Namespace),
		opts:   opts,
	}, nil
}

// Sign will sign a request against the manager's configured client.
func (m *manager) Sign(ctx context.Context, identities string, csrPEM []byte, duration time.Duration, usages []cmapi.KeyUsage) (Bundle, error) {
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "istio-csr-",
			Annotations: map[string]string{
				identityAnnotation: identities,
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				Duration: duration,
			},
			IsCA:      false,
			Request:   csrPEM,
			Usages:    usages,
			IssuerRef: m.opts.IssuerRef,
		},
	}

	// Create CertificateRequest and wait for it to be successfully signed.
	cr, err := m.client.Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		return Bundle{}, fmt.Errorf("failed to create CertificateRequest: %w", err)
	}

	log := m.log.WithValues("namespace", cr.Namespace, "name", cr.Name, "identity", identities)
	log.V(2).Info("created CertificateRequest")

	// If we are not preserving CertificateRequests, always delete from
	// Kubernetes on return.
	if !m.opts.PreserveCertificateRequests {
		defer func() {
			// Use go routine to prevent blocking on Delete call.
			go func() {
				// Use the Background context so that this call is not cancelled by the
				// gRPC context closing.
				if err := m.client.Delete(context.Background(), cr.Name, metav1.DeleteOptions{}); err != nil {
					log.Error(err, "failed to delete CertificateRequest")
					return
				}

				log.V(2).Info("deleted CertificateRequest")
			}()
		}()
	}

	signedCR, err := m.waitForCertificateRequest(ctx, log, cr)
	if err != nil {
		return Bundle{}, fmt.Errorf("failed to wait for CertificateRequest %s/%s to be signed: %w",
			cr.Namespace, cr.Name, err)
	}

	log.V(2).Info("signed CertificateRequest")

	return Bundle{Certificate: signedCR.Status.Certificate, CA: signedCR.Status.CA}, nil
}

// waitForCertificateRequest will set a watch for the CertificateRequest, and
// will return the CertificateRequest once it has reached a terminal state. If
// the terminal state is either Denied or Failed, then this will also return an
// error.
func (m *manager) waitForCertificateRequest(ctx context.Context, log logr.Logger, cr *cmapi.CertificateRequest) (*cmapi.CertificateRequest, error) {
	watcher, err := m.client.Watch(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, cr.Name).String(),
	})
	if err != nil {
		return cr, fmt.Errorf("failed to build watcher for CertificateRequest: %w", err)
	}
	defer watcher.Stop()

	// Get the request in-case it has already reached a terminal state.
	cr, err = m.client.Get(ctx, cr.Name, metav1.GetOptions{})
	if err != nil {
		return cr, fmt.Errorf("failed to get CertificateRequest: %w", err)
	}

	for {
		if apiutil.CertificateRequestIsDenied(cr) {
			return cr, fmt.Errorf("created CertificateRequest has been denied: %v", cr.Status.Conditions)
		}

		if apiutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmmeta.ConditionFalse,
			Reason: cmapi.CertificateRequestReasonFailed,
		}) {
			return cr, fmt.Errorf("created CertificateRequest has failed: %v", cr.Status.Conditions)
		}

		if len(cr.Status.Certificate) > 0 {
			return cr, nil
		}

		log.V(3).Info("waiting for CertificateRequest to become ready")

		for {
			w := <-watcher.ResultChan()
			if w.Type == watch.Deleted {
				return cr, errors.New("created CertificateRequest has been unexpectedly deleted")
			}

			var ok bool
			cr, ok = w.Object.(*cmapi.CertificateRequest)
			if !ok {
				log.Error(nil, "got unexpected object response from watcher", "object", w.Object)
				continue
			}
			break
		}
	}
}
