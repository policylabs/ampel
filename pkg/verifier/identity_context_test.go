// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"

	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/require"
)

func exact(s string) *sapi.StringMatcher {
	return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Exact{Exact: s}}
}

func fromContext(name string) *sapi.StringMatcher {
	return &sapi.StringMatcher{FromContext: name}
}

func sigstoreID(srcRepoMatch *sapi.StringMatcher) *sapi.Identity {
	return &sapi.Identity{
		Sigstore: &sapi.IdentitySigstore{
			IssuerMatch:              exact("https://token.actions.githubusercontent.com"),
			IdentityMatch:            &sapi.StringMatcher{Kind: &sapi.StringMatcher_Regex{Regex: ".*"}},
			SourceRepositoryUriMatch: srcRepoMatch,
		},
	}
}

func TestResolvePolicyIdentities(t *testing.T) {
	t.Parallel()
	const repo = "https://github.com/myorg/repo"

	t.Run("resolves-source-repo-from-context", func(t *testing.T) {
		t.Parallel()
		in := []*sapi.Identity{sigstoreID(fromContext("source_repo"))}
		out, err := resolvePolicyIdentities(in, map[string]any{"source_repo": repo})
		require.NoError(t, err)
		got := out[0].GetSigstore().GetSourceRepositoryUriMatch()
		require.Equal(t, repo, got.GetExact())
		require.Empty(t, got.GetFromContext())
		// The input must be cloned, not resolved in place.
		require.Equal(t, "source_repo", in[0].GetSigstore().GetSourceRepositoryUriMatch().GetFromContext())
	})

	t.Run("missing-context-fails-closed", func(t *testing.T) {
		t.Parallel()
		_, err := resolvePolicyIdentities(
			[]*sapi.Identity{sigstoreID(fromContext("source_repo"))}, map[string]any{},
		)
		require.Error(t, err)
	})

	t.Run("empty-context-value-fails-closed", func(t *testing.T) {
		t.Parallel()
		_, err := resolvePolicyIdentities(
			[]*sapi.Identity{sigstoreID(fromContext("source_repo"))},
			map[string]any{"source_repo": ""},
		)
		require.Error(t, err)
	})

	t.Run("non-string-context-value-fails-closed", func(t *testing.T) {
		t.Parallel()
		_, err := resolvePolicyIdentities(
			[]*sapi.Identity{sigstoreID(fromContext("source_repo"))},
			map[string]any{"source_repo": 42},
		)
		require.Error(t, err)
	})

	// from_context is only honored on source_repository_uri_match; on any other
	// matcher it must be rejected (not silently ignored), since a dropped field
	// in nonSourceRepoMatchers would otherwise leak past the scope check.
	t.Run("from-context-out-of-scope-rejected", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name string
			id   *sapi.Identity
		}{
			{"sigstore-issuer", &sapi.Identity{Sigstore: &sapi.IdentitySigstore{IssuerMatch: fromContext("x")}}},
			{"key-id", &sapi.Identity{Key: &sapi.IdentityKey{IdMatch: fromContext("x")}}},
			{"spiffe-path", &sapi.Identity{Spiffe: &sapi.IdentitySpiffe{PathMatch: fromContext("x")}}},
			{"outer-matcher", &sapi.Identity{Matchers: []*sapi.Matcher{{Kind: &sapi.Matcher_String_{String_: fromContext("x")}}}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				_, err := resolvePolicyIdentities([]*sapi.Identity{tc.id}, map[string]any{"x": "v"})
				require.Error(t, err)
			})
		}
	})

	t.Run("no-from-context-unchanged-and-cloned", func(t *testing.T) {
		t.Parallel()
		in := []*sapi.Identity{sigstoreID(exact(repo))}
		out, err := resolvePolicyIdentities(in, map[string]any{"source_repo": "other"})
		require.NoError(t, err)
		require.Equal(t, repo, out[0].GetSigstore().GetSourceRepositoryUriMatch().GetExact())
		require.NotSame(t, in[0], out[0])
	})

	t.Run("empty-identities", func(t *testing.T) {
		t.Parallel()
		out, err := resolvePolicyIdentities(nil, map[string]any{})
		require.NoError(t, err)
		require.Empty(t, out)
	})
}
