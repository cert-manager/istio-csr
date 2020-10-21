package util

import (
	"context"
	"fmt"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// WaitForCertificateRequestReady waits for the CertificateRequest resource to
// enter a Ready state.
func WaitForCertificateRequestReady(ctx context.Context, log *logrus.Entry, cmclient cmclient.CertificateRequestInterface,
	name string, timeout time.Duration) (*cmapi.CertificateRequest, error) {
	var (
		cr  *cmapi.CertificateRequest
		err error
	)

	err = wait.PollImmediate(time.Second/2, timeout,
		func() (bool, error) {
			cr, err = cmclient.Get(ctx, name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				//log.Info().Msgf("Failed to find CertificateRequest %s/%s", cm.namespace, name)
				return false, nil
			}

			if err != nil {
				return false, fmt.Errorf("error getting CertificateRequest %s: %v", name, err)
			}

			isReady := certificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
			})
			if !isReady {
				log.Debugf("waiting for CertificateRequest to become ready: %+v", cr.Status.Conditions)
			}

			return isReady, nil
		},
	)

	// return certificate even when error to use for debugging
	return cr, err
}

// LogWithCertificateRequest will create a log entry with details about the
// given CertificateRequest
func LogWithCertificateRequest(log *logrus.Entry, cr *cmapi.CertificateRequest) *logrus.Entry {
	return log.WithField("name", cr.Name).WithField("namespace", cr.Namespace)
}

// certificateRequestHasCondition will return true if the given
// CertificateRequest has a condition matching the provided
// CertificateRequestCondition. Only the Type and Status field will be used in
// the comparison, meaning that this function will return 'true' even if the
// Reason, Message and LastTransitionTime fields do not match.
func certificateRequestHasCondition(cr *cmapi.CertificateRequest, c cmapi.CertificateRequestCondition) bool {
	if cr == nil {
		return false
	}
	existingConditions := cr.Status.Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status {
			if c.Reason == "" || c.Reason == cond.Reason {
				return true
			}
		}
	}
	return false
}
