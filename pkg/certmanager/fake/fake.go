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

package fake

import (
	"context"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	"github.com/cert-manager/istio-csr/pkg/certmanager"
)

type signFn func(context.Context, string, []byte, time.Duration, []cmapi.KeyUsage) (certmanager.Bundle, error)

type Fake struct {
	sign signFn
}

func New() *Fake {
	return &Fake{
		sign: func(context.Context, string, []byte, time.Duration, []cmapi.KeyUsage) (certmanager.Bundle, error) {
			return certmanager.Bundle{}, nil
		},
	}
}

func (f *Fake) WithSign(fn signFn) *Fake {
	f.sign = fn
	return f
}

func (f *Fake) Sign(ctx context.Context, identities string, csrPEM []byte, duration time.Duration, usages []cmapi.KeyUsage) (certmanager.Bundle, error) {
	return f.sign(ctx, identities, csrPEM, duration, usages)
}
