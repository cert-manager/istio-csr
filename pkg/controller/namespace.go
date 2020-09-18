package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/util/workqueue"
)

const (
	resyncPeriod        = time.Second * 60
	IstioConfigLabelKey = "istio.io/config"
)

// CARoot manages reconciles a configmap in each namespace with a desired set of data.
type CARoot struct {
	data                    map[string]string
	configMapName           string
	leaderElectionNamespace string

	log    *logrus.Entry
	client kubernetes.Interface

	workqueue          workqueue.RateLimitingInterface
	namespacesInformer cache.SharedInformer
	configMapInformer  cache.SharedInformer

	configMapLister corev1listers.ConfigMapLister
	namespaceLister corev1listers.NamespaceLister
}

func NewCARootController(log *logrus.Entry, kubeClient kubernetes.Interface,
	leaderElectionNamepace string, configMapName string, data map[string]string) *CARoot {
	return &CARoot{
		data:                    data,
		configMapName:           configMapName,
		leaderElectionNamespace: leaderElectionNamepace,
		log:                     log.WithField("module", "ca-root-controller"),
		client:                  kubeClient,
		workqueue:               workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}
}

func (c *CARoot) Run(ctx context.Context, id string) {
	rl := resourcelock.ConfigMapLock{
		ConfigMapMeta: metav1.ObjectMeta{
			Namespace: c.leaderElectionNamespace,
			Name:      "cert-manager-istio-agent",
		},
		Client: c.client.CoreV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id + "-cert-manager-istio-agent",
		},
	}

	cancel := func() {}
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		ReleaseOnCancel: true,
		Lock:            &rl,
		LeaseDuration:   60 * time.Second,
		RenewDeadline:   40 * time.Second,
		RetryPeriod:     15 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				c.log.Info("acquired leader election")
				ctx, cancel = context.WithCancel(ctx)
				for {
					if err := c.runController(ctx); err != nil {
						c.log.Errorf("failed to run controller: %s", err)
						time.Sleep(time.Second)
						continue
					}

					break
				}
			},

			OnStoppedLeading: func() {
				c.log.Info("lost leader election")
				cancel()
			},
		},
	})
}

func (c *CARoot) runController(ctx context.Context) error {
	c.log.Info("starting control loop")

	sharedInformerFactory := informers.NewSharedInformerFactoryWithOptions(c.client, resyncPeriod)
	c.namespacesInformer = sharedInformerFactory.Core().V1().Namespaces().Informer()
	c.namespaceLister = sharedInformerFactory.Core().V1().Namespaces().Lister()
	c.namespacesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.addNamespace,
		UpdateFunc: func(_, new interface{}) {
			c.addNamespace(new)
		},
		// We do not want to sync if the namespace is deleted.
		DeleteFunc: nil,
	})

	c.configMapInformer = sharedInformerFactory.Core().V1().ConfigMaps().Informer()
	c.configMapLister = sharedInformerFactory.Core().V1().ConfigMaps().Lister()
	c.configMapInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.addConfigMap,
		UpdateFunc: func(_, obj interface{}) {
			c.addConfigMap(obj)
		},
		DeleteFunc: c.addConfigMap,
	})

	sharedInformerFactory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.namespacesInformer.HasSynced) ||
		!cache.WaitForCacheSync(ctx.Done(), c.configMapInformer.HasSynced) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	c.log.Info("starting workers")
	for i := 0; i < 5; i++ {
		go wait.Until(func() { c.runWorker(ctx) }, time.Second, ctx.Done())
	}

	<-ctx.Done()
	c.log.Info("shutting down controller")
	c.workqueue.ShutDown()

	return nil
}

func (c *CARoot) addNamespace(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return
	}

	_, ns, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return
	}

	c.workqueue.AddRateLimited(ns)
}

func (c *CARoot) addConfigMap(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		c.log.Errorf("failed to get namespace key: %s", err)
		return
	}

	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		c.log.Errorf("failed to split namespace key: %s", err)
		return
	}

	if name != c.configMapName {
		return
	}

	c.workqueue.AddRateLimited(ns)
}

func (c *CARoot) runWorker(ctx context.Context) {
	for {
		obj, shutdown := c.workqueue.Get()
		if shutdown {
			return
		}

		ns, ok := obj.(string)
		if !ok {
			return
		}

		if err := c.processNamespace(ctx, ns); err != nil {
			c.log.Error(err.Error())
		}
	}
}

func (c *CARoot) processNamespace(ctx context.Context, nsName string) error {
	defer c.workqueue.Done(nsName)

	ns, err := c.namespaceLister.Get(nsName)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get namespace %s", nsName)
	}

	if ns.Status.Phase == corev1.NamespaceTerminating {
		return nil
	}

	cm, err := c.configMapLister.ConfigMaps(nsName).Get(c.configMapName)
	if apierrors.IsNotFound(err) {
		return c.createConfigMap(ctx, nsName)
	}
	if err != nil {
		return err
	}

	var notMatch bool
	for k, v := range c.data {
		if kv, ok := cm.Data[k]; !ok || v != kv {
			cm.Data[k] = v
			notMatch = true
		}
	}

	if notMatch {
		cm.Labels[IstioConfigLabelKey] = "true"

		c.log.Debugf("updating configmap %s/%s", cm.Namespace, cm.Name)
		if _, err := c.client.CoreV1().ConfigMaps(nsName).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (c *CARoot) createConfigMap(ctx context.Context, ns string) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.configMapName,
			Namespace: ns,
			Labels: map[string]string{
				IstioConfigLabelKey: "true",
			},
		},
		Data: c.data,
	}

	c.log.Debugf("creating configmap %s/%s", cm.Namespace, cm.Name)
	if _, err := c.client.CoreV1().ConfigMaps(ns).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func convertToConfigMap(obj interface{}) (*corev1.ConfigMap, error) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %#v", obj)
		}
		cm, ok = tombstone.Obj.(*corev1.ConfigMap)
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not a ConfigMap %#v", obj)
		}
	}
	return cm, nil
}
