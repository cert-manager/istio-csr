/*
Copyright 2024 The cert-manager Authors.

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

package istiodcert

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeDNSNamesFromRevisions(t *testing.T) {
	type testCase struct {
		name      string
		namespace string
		revisions []string
	}

	tests := []testCase{
		{
			name:      "empty-revisions",
			namespace: "test1",
		},
		{
			name:      "default-only-revision",
			namespace: "test2",
			revisions: []string{"default"},
		},
		{
			name:      "default-first-among-revisions",
			namespace: "test3",
			revisions: []string{"default", "1-21-0", "1-22-1"},
		},
		{
			name:      "default-among-revisions",
			namespace: "test3",
			revisions: []string{"1-21-0", "default", "1-22-1"},
		},
		{
			name:      "non-default-revisions",
			namespace: "test4",
			revisions: []string{"1-21-0", "1-22-1"},
		},
		{
			name:      "duplicate-revisions",
			namespace: "test5",
			revisions: []string{"default", "1-21-0", "default", "1-22-1", "1-21-0"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectedRevisionPrefix := "istiod-"
			expectedSuffix := fmt.Sprintf(".%s.svc", tc.namespace)
			expectedCommonName := "istiod" + expectedSuffix

			commonName, dnsNames := makeDNSNamesFromRevisions(tc.namespace, tc.revisions)

			assert.Equal(t, expectedCommonName, commonName,
				"The commonName should always be istiod.<namespace>.svc")

			foundRevisions := make([]string, len(dnsNames))
			for i, dnsName := range dnsNames {
				var revision string
				if dnsName == commonName {
					revision = "default"
				} else {
					revision = dnsName[len(expectedRevisionPrefix) : len(dnsName)-len(expectedSuffix)]
				}
				foundRevisions[i] = revision
			}

			if len(tc.revisions) == 0 {
				assert.Equal(t, []string{commonName}, dnsNames,
					"The dnsNames should contain only the commonName if the supplied revisions list is empty")
			} else {
				assert.Equal(t, tc.revisions, foundRevisions,
					"The original ordered revisions should be recoverable from the DNS names")
			}
		})
	}
}
