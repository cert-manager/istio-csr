package controller

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/cert-manager/istio-csr/cmd/app/options"
)

const (
	IstioConfigLabelKey = "istio.io/config"
)

// CARoot manages reconciles a configmap in each namespace with a desired set of data.
type CARoot struct {
	log *logrus.Entry
	mgr manager.Manager
}

type namespace struct {
	log    *logrus.Entry
	client client.Client
	*enforcer
}

type configmap struct {
	client client.Client
	*enforcer
}

type enforcer struct {
	log           *logrus.Entry
	client        client.Client
	data          map[string]string
	configMapName string
}

func NewCARootController(opts *options.Options, data map[string]string, healthz healthz.Checker) (*CARoot, error) {
	log := opts.Logr.WithField("module", "ca-root-controller")

	scheme := runtime.NewScheme()
	if err := k8sscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add kubernetes scheme: %s", err)
	}

	// hostname used as the leader election ID.
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname for election ID: %s", err)
	}

	mgr, err := ctrl.NewManager(opts.KubeOptions.RestConfig, ctrl.Options{
		Scheme:                  scheme,
		LeaderElection:          true,
		LeaderElectionNamespace: opts.Namespace,
		LeaderElectionID:        hostname,
		ReadinessEndpointName:   opts.ReadyzPath,
		HealthProbeBindAddress:  fmt.Sprintf("0.0.0.0:%d", opts.ReadyzPort),
		// TODO: fix logger
		//Logger:                  log.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to start manager: %s", err)
	}

	if err := mgr.AddReadyzCheck("istio-csr", healthz); err != nil {
		return nil, fmt.Errorf("failed to add istio-csr readiness checks: %s", err)
	}

	enforcer := &enforcer{
		client:        mgr.GetClient(),
		data:          data,
		configMapName: opts.RootCAConfigMapName,
		log:           log,
	}

	namespace := &namespace{
		log:      log,
		client:   mgr.GetClient(),
		enforcer: enforcer,
	}
	configmap := &configmap{
		client:   mgr.GetClient(),
		enforcer: enforcer,
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(new(corev1.Namespace)).
		Complete(namespace); err != nil {
		return nil, fmt.Errorf("failed to create namespace controller: %s", err)
	}

	// Only reconcile config maps that match the well known name
	if err := ctrl.NewControllerManagedBy(mgr).
		For(new(corev1.ConfigMap)).
		WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			if obj.GetName() != opts.RootCAConfigMapName {
				return false
			}
			return true
		})).
		Complete(configmap); err != nil {
		return nil, fmt.Errorf("failed to create configmap controller: %s", err)
	}

	return &CARoot{
		mgr: mgr,
		log: log,
	}, nil
}

// Run starts the controller. This is a blocking function.
func (c *CARoot) Run(ctx context.Context) error {
	c.log.Info("starting controller")
	return c.mgr.Start(ctx)
}

// Reconcile is called when a ConfigMap event occurs where the resource has the
// well known name in the target Kubernetes cluster. Reconcile will ensure that
// the ConfigMap exists, and the CA root bundle is present.
func (c *configmap) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if err := c.configmap(ctx, req.NamespacedName.Namespace); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// Reconcile is called when any Namespace event occurs in the target Kubernetes
// cluster. If the resource exists, Reconcile will ensure that the ConfigMap
// exists, CA root bundle is present.
func (n *namespace) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ns := new(corev1.Namespace)

	// Attempt to get the synced Namespace. If the resource no longer
	// exists, we can ignore it.
	err := n.client.Get(ctx, req.NamespacedName, ns)
	if apierrors.IsNotFound(err) {
		n.log.WithField("namespace", req.Name).Debug("namespace doesn't exist, ignoring")
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get %q: %s", req.NamespacedName, err)
	}

	// If the namespace is terminating, we should reconcile configmap
	if ns.Status.Phase == corev1.NamespaceTerminating {
		return ctrl.Result{}, nil
	}

	if err := n.configmap(ctx, ns.Name); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// configmap will ensure that the provided namespace has the correct ConfigMap,
// with the correct data and label.
func (e *enforcer) configmap(ctx context.Context, namespace string) error {
	var (
		namespacedName = types.NamespacedName{
			Name:      e.configMapName,
			Namespace: namespace,
		}
		cm = new(corev1.ConfigMap)
	)

	log := e.log.WithField("configmap", namespacedName.String())
	err := e.client.Get(ctx, namespacedName, cm)
	if apierrors.IsNotFound(err) {
		log.Debug("configmap doesn't exist, creating")

		return e.client.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      e.configMapName,
				Namespace: namespace,
				Labels: map[string]string{
					IstioConfigLabelKey: "true",
				},
			},
			Data: e.data,
		})
	}
	if err != nil {
		return fmt.Errorf("failed to get %q: %s", namespacedName, err)
	}

	var notMatch bool
	for k, v := range e.data {
		if kv, ok := cm.Data[k]; !ok || v != kv {
			if cm.Data == nil {
				cm.Data = make(map[string]string)
			}

			cm.Data[k] = v
			notMatch = true
		}
	}

	if val, ok := cm.Labels[IstioConfigLabelKey]; !ok || val != "true" {
		notMatch = true
	}

	if notMatch {
		if cm.Labels == nil {
			cm.Labels = make(map[string]string)
		}

		cm.Labels[IstioConfigLabelKey] = "true"

		log.Debugf("updating configmap %q", namespacedName)
		if err := e.client.Update(ctx, cm); err != nil {
			return err
		}
	}

	return nil
}
