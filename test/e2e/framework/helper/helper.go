package helper

import (
	"context"
	"fmt"
	"time"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmversioned "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

type Helper struct {
	cmclient cmversioned.Interface
}

func NewHelper(cmclient cmversioned.Interface) *Helper {
	return &Helper{
		cmclient: cmclient,
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
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
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
