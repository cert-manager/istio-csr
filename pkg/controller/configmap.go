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

	"github.com/cert-manager/istio-csr/pkg/tls"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	configMapNameIstioRoot = "istio-ca-root-cert"
	configMapLabelKey      = "istio.io/config"
)

type Options struct {
	// LeaderElectionNamespace is the namespace that will be used to lease the
	// leader election of each controller.
	LeaderElectionNamespace string

	// TLS is the tls provider that is used for updating the config map.
	TLS tls.Interface

	// Manager is the controller-runtime Manager that the controller will be
	// registered against.
	Manager manager.Manager
}

// configmap is the controller that is responsible for ensuring that all
// namespaces have the correct ConfigMap with the istio root CA.
type configmap struct {
	// client is a Kubernetes client that makes calls to the API for every
	// request.
	// Should be used for creating and updating resources.
	// This is a seperate delegating client which doesn't cache ConfigMaps, see
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
}

func AddConfigMapController(ctx context.Context, log logr.Logger, opts Options) error {
	noCacheClient, err := client.NewDelegatingClient(client.NewDelegatingClientInput{
		CacheReader:       opts.Manager.GetCache(),
		Client:            opts.Manager.GetClient(),
		UncachedObjects:   []client.Object{new(corev1.ConfigMap)},
		CacheUnstructured: false,
	})
	if err != nil {
		return fmt.Errorf("failed to build non-cached client for ConfigMaps: %w", err)
	}

	c := &configmap{
		client: noCacheClient,
		lister: opts.Manager.GetCache(),
		log:    log.WithName("controller").WithName("configmap"),
		tls:    opts.TLS,
	}

	return ctrl.NewControllerManagedBy(opts.Manager).
		// Reconcile ConfigMaps but only cache metadata
		For(new(corev1.ConfigMap), builder.OnlyMetadata, builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			// Only process ConfigMaps with the istio configmap name
			return obj.GetName() == configMapNameIstioRoot
		}))).

		// Watch all Namespaces. Cache whole Namespace to include Phase Status.
		Watches(&source.Kind{Type: new(corev1.Namespace)}, handler.EnqueueRequestsFromMapFunc(
			func(obj client.Object) []reconcile.Request {
				return []reconcile.Request{reconcile.Request{NamespacedName: types.NamespacedName{Namespace: obj.GetName(), Name: configMapNameIstioRoot}}}
			},
		)).

		// If the CA roots change then reconcile all ConfigMaps
		Watches(&source.Channel{Source: c.tls.SubscribeRootCAsEvent()}, handler.EnqueueRequestsFromMapFunc(
			func(obj client.Object) []reconcile.Request {
				var namespaceList corev1.NamespaceList
				if err := c.lister.List(ctx, &namespaceList); err != nil {
					c.log.Error(err, "failed to list namespaces, exiting...")
					os.Exit(0)
				}
				var requests []reconcile.Request
				for _, namespace := range namespaceList.Items {
					requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace.Name, Name: configMapNameIstioRoot}})
				}
				return requests
			},
		)).

		// Complete controller.
		Complete(c)
}

// Reconcile is the main ConfigMap Reconcile loop. It will ensure that the
// istio ConfigMap exists, and has the correct CA entry.
func (c *configmap) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.log.WithValues("namespace", req.Namespace, "configmap", configMapNameIstioRoot)
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

	if namespace.Status.Phase == corev1.NamespaceTerminating {
		log.V(2).WithValues("phase", corev1.NamespaceTerminating).Info("skipping sync for namespace as it is terminating")
		return ctrl.Result{}, nil
	}

	rootCAsPEM := string(c.tls.RootCAs().PEM)

	// Check ConfigMap exists, and has the correct data.
	var configMap corev1.ConfigMap
	err = c.client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: configMapNameIstioRoot}, &configMap)

	// If the ConfigMap doesn't exist, create it with the correct data
	if apierrors.IsNotFound(err) {
		log.Info("creating configmap with root CA data")
		return ctrl.Result{}, c.client.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configMapNameIstioRoot,
				Namespace: req.Namespace,
				Labels:    map[string]string{configMapLabelKey: "true"},
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

	// If the ConfigMap doesn't have the expected label, update.
	if v, ok := configMap.Labels[configMapLabelKey]; !ok || v != "true" {
		configMap.Labels[configMapLabelKey] = "true"
		updateNeeded = true
	}

	if updateNeeded {
		log.V(3).Info("updating ConfigMap")
		return ctrl.Result{}, c.client.Update(ctx, &configMap)
	}

	log.V(3).Info("no update needed")

	return ctrl.Result{}, nil
}
