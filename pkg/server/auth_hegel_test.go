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

package server

import (
	"net/url"
	"testing"

	"hegel.dev/go/hegel"
)

// TestIdentitiesMatchProperty: identitiesMatch(a, b) holds iff a and the
// string forms of b are equal as multisets — order never matters, but
// duplicates, missing and extra entries always do. The oracle recomputes
// multiset equality by counting, independently of the sort-based
// implementation. Replaces the example table, whose rows instantiated the
// same rule.
func TestIdentitiesMatchProperty(t *testing.T) {
	pool := []string{
		"spiffe://foo.bar",
		"spiffe://cluster.local/ns/a/sa/x",
		"spiffe://cluster.local/ns/a/sa/y",
	}

	drawIdentities := func(ht *hegel.T) []string {
		var out []string
		for _, i := range hegel.Draw(ht, hegel.Lists(hegel.Integers(0, len(pool)-1)).MaxSize(4)) {
			out = append(out, pool[i])
		}
		return out
	}

	hegel.Test(t, func(ht *hegel.T) {
		a := drawIdentities(ht)

		var b []string
		if hegel.Draw(ht, hegel.Booleans()) {
			// A permutation of a: reversal plus a drawn rotation.
			b = append(b, a...)
			for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
				b[i], b[j] = b[j], b[i]
			}
			if len(b) > 1 {
				n := hegel.Draw(ht, hegel.Integers(0, len(b)-1))
				b = append(b[n:], b[:n]...)
			}
		} else {
			b = drawIdentities(ht)
		}

		urls := make([]*url.URL, 0, len(b))
		for _, s := range b {
			u, err := url.Parse(s)
			if err != nil {
				ht.Fatalf("failed to parse %q: %v", s, err)
			}
			urls = append(urls, u)
		}

		counts := map[string]int{}
		for _, s := range a {
			counts[s]++
		}
		for _, s := range b {
			counts[s]--
		}
		want := true
		for _, c := range counts {
			if c != 0 {
				want = false
			}
		}

		if got := identitiesMatch(a, urls); got != want {
			ht.Fatalf("identitiesMatch(%v, %v) = %t, want %t", a, b, got, want)
		}
	}, hegel.WithTestCases(1000))
}
