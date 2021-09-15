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
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/watch"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/klog/v2/klogr"

	"github.com/cert-manager/istio-csr/test/gen"
)

func Test_Sign(t *testing.T) {
	tests := map[string]struct {
		client      func() *fake.Clientset
		preserveCRs bool

		expBundle Bundle
		expObject bool
		expErr    bool
	}{
		"preserveCRs=true if request is denied, return error": {
			client: func() *fake.Clientset {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Modify(gen.CertificateRequest("test-cr",
							gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:   cmapi.CertificateRequestConditionDenied,
								Status: cmmeta.ConditionTrue,
							}),
						))
					}()
					return true, watcher, nil
				})
				return client
			},
			preserveCRs: true,

			expObject: true,
			expBundle: Bundle{},
			expErr:    true,
		},

		"preserveCRs=false if request is denied, return error and delete object": {
			client: func() *fake.Clientset {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Modify(gen.CertificateRequest("test-cr",
							gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:   cmapi.CertificateRequestConditionDenied,
								Status: cmmeta.ConditionTrue,
							}),
						))
					}()
					return true, watcher, nil
				})
				return client
			},
			preserveCRs: false,

			expObject: false,
			expBundle: Bundle{},
			expErr:    true,
		},

		"preserveCRs=true if request is failed, return error": {
			client: func() *fake.Clientset {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Modify(gen.CertificateRequest("test-cr",
							gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionFalse,
								Reason: cmapi.CertificateRequestReasonFailed,
							}),
						))
					}()
					return true, watcher, nil
				})
				return client
			},
			preserveCRs: true,

			expObject: true,
			expBundle: Bundle{},
			expErr:    true,
		},

		"preserveCRs=false if request is failed, return error and delete object": {
			client: func() *fake.Clientset {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Modify(gen.CertificateRequest("test-cr",
							gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionFalse,
								Reason: cmapi.CertificateRequestReasonFailed,
							}),
						))
					}()
					return true, watcher, nil
				})
				return client
			},
			preserveCRs: false,

			expObject: false,
			expBundle: Bundle{},
			expErr:    true,
		},

		"preserveCRs=true if request is signed, return bundle": {
			client: func() *fake.Clientset {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Modify(gen.CertificateRequest("test-cr",
							gen.SetCertificateRequestCertificate([]byte("signed-cert")),
							gen.SetCertificateRequestCA([]byte("ca")),
						))
					}()
					return true, watcher, nil
				})
				return client
			},
			preserveCRs: true,

			expObject: true,
			expBundle: Bundle{
				Certificate: []byte("signed-cert"),
				CA:          []byte("ca"),
			},
			expErr: false,
		},

		"preserveCRs=false if request is signed, return bundle and delete object": {
			client: func() *fake.Clientset {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Modify(gen.CertificateRequest("test-cr",
							gen.SetCertificateRequestCertificate([]byte("signed-cert")),
							gen.SetCertificateRequestCA([]byte("ca")),
						))
					}()
					return true, watcher, nil
				})
				return client
			},
			preserveCRs: false,

			expObject: false,
			expBundle: Bundle{
				Certificate: []byte("signed-cert"),
				CA:          []byte("ca"),
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := test.client()
			m := &manager{
				client: client.CertmanagerV1().CertificateRequests(gen.DefaultTestNamespace),
				log:    klogr.New(),
				opts: Options{
					PreserveCertificateRequests: test.preserveCRs,
				},
			}

			bundle, err := m.Sign(context.TODO(), "", nil, 0, nil)
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v", test.expErr, err)
			}

			// Wait for delete go routine to finish
			time.Sleep(time.Millisecond * 50)

			if !apiequality.Semantic.DeepEqual(bundle, test.expBundle) {
				t.Errorf("unexpected returned bundle, exp=%v got=%v", test.expBundle, bundle)
			}

			var deleted bool
			for _, a := range client.Fake.Actions() {
				if a.GetVerb() == "delete" {
					deleted = true
					break
				}
			}

			if test.expObject == deleted {
				t.Errorf("unexpected returned CertificateRequest remaining, exp=%t got=%t", test.expObject, !deleted)
			}
		})
	}
}

func Test_waitForCertificateRequest(t *testing.T) {
	tests := map[string]struct {
		client func() cmclient.CertificateRequestInterface

		expResult *cmapi.CertificateRequest
		expErr    bool
	}{
		"if the request does not exist, should return with error": {
			client: func() cmclient.CertificateRequestInterface {
				return fake.NewSimpleClientset().CertmanagerV1().CertificateRequests(gen.DefaultTestNamespace)
			},

			expResult: nil,
			expErr:    true,
		},
		"if the request is denied, should return with error": {
			client: func() cmclient.CertificateRequestInterface {
				return fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr",
						gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionDenied,
							Status: cmmeta.ConditionTrue,
						}),
					)).CertmanagerV1().CertificateRequests(gen.DefaultTestNamespace)
			},

			expResult: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:   cmapi.CertificateRequestConditionDenied,
					Status: cmmeta.ConditionTrue,
				})),
			expErr: true,
		},

		"if the request has failed, should return with error": {
			client: func() cmclient.CertificateRequestInterface {
				return fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr",
						gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
							Type:   cmapi.CertificateRequestConditionReady,
							Status: cmmeta.ConditionFalse,
							Reason: cmapi.CertificateRequestReasonFailed,
						}),
					)).CertmanagerV1().CertificateRequests(gen.DefaultTestNamespace)
			},

			expResult: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionFalse,
					Reason: cmapi.CertificateRequestReasonFailed,
				})),
			expErr: true,
		},

		"if the request has been signed, should return with no error": {
			client: func() cmclient.CertificateRequestInterface {
				return fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr",
						gen.SetCertificateRequestCertificate([]byte("signed-cert")),
					),
				).CertmanagerV1().CertificateRequests(gen.DefaultTestNamespace)
			},

			expResult: gen.CertificateRequest("test-cr",
				gen.SetCertificateRequestCertificate([]byte("signed-cert")),
			),
			expErr: false,
		},

		"if the request is not signed then receives denied update, should return with error": {
			client: func() cmclient.CertificateRequestInterface {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Modify(gen.CertificateRequest("test-cr",
							gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:   cmapi.CertificateRequestConditionDenied,
								Status: cmmeta.ConditionTrue,
							}),
						))
					}()
					return true, watcher, nil
				})
				return client.CertmanagerV1().CertificateRequests(gen.DefaultTestNamespace)
			},

			expResult: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:   cmapi.CertificateRequestConditionDenied,
					Status: cmmeta.ConditionTrue,
				}),
			),
			expErr: true,
		},
		"if the request is not signed then receives failed update, should return with error": {
			client: func() cmclient.CertificateRequestInterface {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Modify(gen.CertificateRequest("test-cr",
							gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionFalse,
								Reason: cmapi.CertificateRequestReasonFailed,
							}),
						))
					}()
					return true, watcher, nil
				})
				return client.CertmanagerV1().CertificateRequests(gen.DefaultTestNamespace)
			},

			expResult: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:   cmapi.CertificateRequestConditionReady,
					Status: cmmeta.ConditionFalse,
					Reason: cmapi.CertificateRequestReasonFailed,
				}),
			),
			expErr: true,
		},
		"if the request is not signed then receives signed update, should return with no error": {
			client: func() cmclient.CertificateRequestInterface {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Modify(gen.CertificateRequest("test-cr",
							gen.SetCertificateRequestCertificate([]byte("signed-cert")),
						))
					}()
					return true, watcher, nil
				})
				return client.CertmanagerV1().CertificateRequests(gen.DefaultTestNamespace)
			},

			expResult: gen.CertificateRequest("test-cr",
				gen.SetCertificateRequestCertificate([]byte("signed-cert")),
			),
			expErr: false,
		},
		"if the request is not signed then gets deleted, should return with error": {
			client: func() cmclient.CertificateRequestInterface {
				client := fake.NewSimpleClientset(
					gen.CertificateRequest("test-cr"),
				)
				client.PrependWatchReactor("*", func(coretesting.Action) (bool, watch.Interface, error) {
					watcher := watch.NewFake()
					go func() {
						watcher.Modify(gen.CertificateRequest("test-cr"))
						watcher.Delete(gen.CertificateRequest("test-cr",
							gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionFalse,
								Reason: "random condition",
							}),
						))
					}()
					return true, watcher, nil
				})
				return client.CertmanagerV1().CertificateRequests(gen.DefaultTestNamespace)
			},

			expResult: gen.CertificateRequest("test-cr"),
			expErr:    true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			m := &manager{
				client: test.client(),
			}

			log := klogr.New()
			cr, err := m.waitForCertificateRequest(context.TODO(), log, gen.CertificateRequest("test-cr"))
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v", test.expErr, err)
			}

			if !apiequality.Semantic.DeepEqual(cr, test.expResult) {
				t.Errorf("unexpected returned CertificateRequest, exp=%#+v got=%#+v", test.expResult, cr)
			}
		})
	}
}
