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

package controller

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/cert-manager/istio-csr/pkg/tls"
)

const (
	// ConfigMapNameIstioRoot is the name of the ConfigMap written into mesh
	// member namespaces containing the Istio root CA. It is hardcoded to match Istio's
	// expected naming convention.
	ConfigMapNameIstioRoot = "istio-ca-root-cert"

	// configMapLabelKey is required by Istio workloads consuming the root CA ConfigMap.
	// Because Istio's namespace controller also applies this label, it cannot be used as
	// an ownership marker when pruning or cleaning up ConfigMaps.
	configMapLabelKey = "istio.io/config"

	// configMapManagedByLabelKey identifies ConfigMaps managed by this controller.
	// Cleanup only deletes objects that carry this label.
	configMapManagedByLabelKey = "istio-csr.cert-manager.io/managed"
)

func istioRootConfigMapLabels() map[string]string {
	return map[string]string{
		configMapLabelKey:          "true",
		configMapManagedByLabelKey: "true",
	}
}

type Options struct {
	// TLS is the tls provider that is used for updating the config map.
	TLS tls.Interface

	// Manager is the controller-runtime Manager that the controller will be
	// registered against.
	Manager manager.Manager

	// NamespaceSelector filters the namespace to creates the istio-ca-root-cert ConfigMap
	ConfigMapNamespaceSelector string

	// MaxConcurrentReconciles is the maximum number of concurrent reconciles.
	MaxConcurrentReconciles int
}

// configmap is the controller that is responsible for ensuring that all
// namespaces have the correct ConfigMap with the istio root CA.
type configmap struct {
	// client is a Kubernetes client that makes calls to the API for every
	// request.
	// Should be used for creating and updating resources.
	// This is a separate delegating client which doesn't cache ConfigMaps, see
	// https://github.com/kubernetes-sigs/controller-runtime/issues/1454
	client client.Client

	// lister makes requests to the informer cache. Beware that resources who's
	// informer only caches metadata, will not return underlying data of that
	// resource. Use client instead.
	lister client.Reader

	// log is the logger used by configmap.
	log logr.Logger

	// tls provides the RootCA data that is propagated.
	tls tls.Interface

	// namespaceSelector filters the namespace to creates the istio-ca-root-cert ConfigMap
	namespaceSelector labels.Selector

	// rootCAsPEM caches the latest Root CA bundle PEM.
	// It is populated on RootCA events and read by reconcile.
	rootCAsPEM string

	// rootCAsMu protects access to rootCAsPEM
	rootCAsMu sync.RWMutex
}

func AddConfigMapController(ctx context.Context, log logr.Logger, opts Options) error {
	// noCacheClient is used to retrieve objects that we don't want to cache.
	noCacheClient, err := client.New(opts.Manager.GetConfig(), client.Options{
		Cache: &client.CacheOptions{
			Reader:       opts.Manager.GetCache(),
			DisableFor:   []client.Object{&corev1.ConfigMap{}},
			Unstructured: false,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to build non-cached client for ConfigMaps: %w", err)
	}

	namespaceSelector, err := labels.Parse(opts.ConfigMapNamespaceSelector)
	if err != nil {
		return fmt.Errorf("failed to parse namespace selector: %w", err)
	}

	c := &configmap{
		client:            noCacheClient,
		lister:            opts.Manager.GetCache(),
		log:               log.WithName("controller").WithName("configmap"),
		tls:               opts.TLS,
		namespaceSelector: namespaceSelector,
	}

	return ctrl.NewControllerManagedBy(opts.Manager).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: opts.MaxConcurrentReconciles,
		}).
		// Reconcile ConfigMaps but only cache metadata
		For(new(corev1.ConfigMap), builder.OnlyMetadata, builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			return obj.GetName() == ConfigMapNameIstioRoot
		}))).

		// Watch all Namespaces. Cache whole Namespace to include Phase Status.
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: obj.GetName(), Name: ConfigMapNameIstioRoot}}}
			},
		)).

		// If the CA roots change then reconcile all ConfigMaps
		WatchesRawSource(source.Channel(c.tls.SubscribeRootCAsEvent(), handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, _ client.Object) []reconcile.Request {

				// Compute RootCAs once per event
				rootCAs := c.tls.RootCAs(ctx)
				if rootCAs == nil {
					c.log.Error(nil, "failed to load RootCAs")
					return nil
				}

				c.rootCAsMu.Lock()
				c.rootCAsPEM = string(rootCAs.PEM)
				c.rootCAsMu.Unlock()

				var namespaceList corev1.NamespaceList
				if err := c.lister.List(ctx, &namespaceList); err != nil {
					c.log.Error(err, "failed to list namespaces, exiting...")
					os.Exit(0)
				}
				var requests []reconcile.Request
				for _, namespace := range namespaceList.Items {
					// Skip namespaces if they do not match the namespace selector
					if !c.namespaceSelector.Matches(labels.Set(namespace.GetLabels())) {
						continue
					}

					requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace.Name, Name: ConfigMapNameIstioRoot}})
				}
				return requests
			},
		))).

		// Complete controller.
		Complete(c)
}

// Reconcile is the main ConfigMap Reconcile loop. It will ensure that the
// istio ConfigMap exists, and has the correct CA entry.
func (c *configmap) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.log.WithValues("namespace", req.Namespace, "configmap", ConfigMapNameIstioRoot)
	log.V(3).Info("syncing configmap")

	// Check Namespace is not deleted and is not in a terminating state.
	var namespace corev1.Namespace
	err := c.lister.Get(ctx, client.ObjectKey{Name: req.Namespace}, &namespace)
	if apierrors.IsNotFound(err) {
		// No need to reconcile the configmap if the namespace is deleted.
		log.V(3).Info("namespace does not exist")
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	// Skip sync and cleanup while the namespace is deleting.
	if !namespace.DeletionTimestamp.IsZero() || namespace.Status.Phase == corev1.NamespaceTerminating {
		log.V(2).WithValues("phase", namespace.Status.Phase).Info("skipping sync for namespace as it is terminating")
		return ctrl.Result{}, nil
	}

	// Namespace no longer matches the selector: remove any leftover root CA ConfigMap.
	if !c.namespaceSelector.Matches(labels.Set(namespace.GetLabels())) {
		return c.deleteRootCAConfigMapIfPresent(ctx, log, req.Namespace)
	}

	c.rootCAsMu.RLock()
	rootCAsPEM := c.rootCAsPEM
	c.rootCAsMu.RUnlock()

	if rootCAsPEM == "" {
		log.V(2).Info("RootCAs cache not ready, requeuing")
		return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
	}

	// Check ConfigMap exists, and has the correct data.
	var configMap corev1.ConfigMap
	err = c.client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: ConfigMapNameIstioRoot}, &configMap)

	// If the ConfigMap doesn't exist, create it with the correct data
	if apierrors.IsNotFound(err) {
		log.Info("creating configmap with root CA data")
		return ctrl.Result{}, c.client.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ConfigMapNameIstioRoot,
				Namespace: req.Namespace,
				Labels:    istioRootConfigMapLabels(),
			},
			Data: map[string]string{
				"root-cert.pem": rootCAsPEM,
			},
		})
	}

	if err != nil {
		return ctrl.Result{}, err
	}

	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}
	if configMap.Labels == nil {
		configMap.Labels = make(map[string]string)
	}

	var updateNeeded bool

	// If the ConfigMap has unexpected keys, delete them
	for k := range configMap.Data {
		if k != "root-cert.pem" {
			updateNeeded = true
			configMap.Data = make(map[string]string)
			break
		}
	}

	// If the ConfigMap doesn't have the expected key value, update.
	if data, ok := configMap.Data["root-cert.pem"]; !ok || data != rootCAsPEM {
		configMap.Data["root-cert.pem"] = rootCAsPEM
		updateNeeded = true
	}

	// Ensure both the Istio compatibility label and ownership marker are set.
	if v, ok := configMap.Labels[configMapLabelKey]; !ok || v != "true" {
		configMap.Labels[configMapLabelKey] = "true"
		updateNeeded = true
	}
	if v, ok := configMap.Labels[configMapManagedByLabelKey]; !ok || v != "true" {
		configMap.Labels[configMapManagedByLabelKey] = "true"
		updateNeeded = true
	}

	if updateNeeded {
		log.Info("updating ConfigMap data")
		return ctrl.Result{}, c.client.Update(ctx, &configMap)
	}

	log.V(3).Info("no update needed")

	return ctrl.Result{}, nil
}

// deleteRootCAConfigMapIfPresent removes istio-ca-root-cert when the namespace no longer
// matches --configmap-namespace-selector. It only deletes ConfigMaps this controller
// owns (labeled istio-csr.cert-manager.io/managed=true).
func (c *configmap) deleteRootCAConfigMapIfPresent(ctx context.Context, log logr.Logger, namespace string) (ctrl.Result, error) {
	var configMap corev1.ConfigMap
	err := c.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ConfigMapNameIstioRoot}, &configMap)
	// NotFound: ConfigMap does not exist, so nothing to clean up.
	// Forbidden/Unauthorized: Missing RBAC permissions to read the ConfigMap;
	// skip cleanup and do not requeue since permissions won't change on retry.
	if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
		log.V(3).Info("namespace does not match selector and ConfigMap is absent or is not accessible")
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	if val, exists := configMap.Labels[configMapManagedByLabelKey]; !exists || val != "true" {
		log.V(2).Info("namespace does not match selector; ignoring ConfigMap not managed by istio-csr",
			"selector", c.namespaceSelector.String())
		return ctrl.Result{}, nil
	}

	log.Info("deleting ConfigMap from the namespace which no longer matches selector",
		"selector", c.namespaceSelector.String())
	// Constrain the delete to the exact object version that passed the ownership check.
	// If the ConfigMap is concurrently replaced or relabeled, the API server returns a
	// Conflict error (requeued by the standard error path) instead of deleting an unmanaged resource.
	if err := c.client.Delete(ctx, &configMap, client.Preconditions{
		UID:             &configMap.UID,
		ResourceVersion: &configMap.ResourceVersion,
	}); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}
