/*
Copyright 2026 The cert-manager Authors.

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

package options

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The args below are what the Helm chart renders for additionalAnnotations
// (see deploy/charts/istio-csr/tests/deployment_test.yaml). This checks they
// parse back to the original annotation values.
func TestAdditionalAnnotationsFlagParsesChartArgs(t *testing.T) {
	tests := map[string]struct {
		args []string
		want map[string]string
	}{
		"simple value": {
			args: []string{`--certificate-request-additional-annotations=a.io/x=istio-csr`},
			want: map[string]string{"a.io/x": "istio-csr"},
		},
		"value with commas and quotes": {
			args: []string{`--certificate-request-additional-annotations=some.cert-manager.io/custom-fields=[{ "Name": "field1", "Value": "value1" },{ "Name": "field2", "Value": "value2" }]`},
			want: map[string]string{"some.cert-manager.io/custom-fields": `[{ "Name": "field1", "Value": "value1" },{ "Name": "field2", "Value": "value2" }]`},
		},
		"value containing =": {
			args: []string{`--certificate-request-additional-annotations="b.io/y=k=v,""q"""`},
			want: map[string]string{"b.io/y": `k=v,"q"`},
		},
		"one flag per annotation": {
			args: []string{
				`--certificate-request-additional-annotations=a.io/x=one`,
				`--certificate-request-additional-annotations=b.io/y=two`,
			},
			want: map[string]string{"a.io/x": "one", "b.io/y": "two"},
		},
		"numeric and boolean values": {
			args: []string{
				`--certificate-request-additional-annotations=a.io/n=42`,
				`--certificate-request-additional-annotations=b.io/b=true`,
			},
			want: map[string]string{"a.io/n": "42", "b.io/b": "true"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var o Options
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			o.addAdditionalAnnotationsFlags(fs)

			require.NoError(t, fs.Parse(test.args))
			assert.Equal(t, test.want, o.CertManager.AdditionalAnnotations)
		})
	}
}
