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

package e2e

import (
	"k8s.io/klog/v2"

	"github.com/cert-manager/istio-csr/test/e2e/framework/config"

	. "github.com/onsi/ginkgo/v2"
)

var (
	cfg = config.GetConfig()
)

var _ = SynchronizedBeforeSuite(func() []byte {
	if err := cfg.Validate(); err != nil {
		klog.Fatalf("Invalid test config: %s", err)
	}

	return nil
}, func([]byte) {
})

var _ = SynchronizedAfterSuite(func() {},
	func() {
	},
)
