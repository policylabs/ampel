// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/policy"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
)

// compileSet compiles a policy set whose policies read a value from the
// set's common context. Verifying the set through the per-policy path loses
// that context and fails with "context value ... is required but not set".
func compileSet(t *testing.T, id, greeting, code string) *papi.PolicySet {
	t.Helper()
	set, _, _, err := policy.NewCompiler().Compile([]byte(`{
		"id": "` + id + `",
		"common": { "context": { "greeting": { "value": "` + greeting + `" } } },
		"policies": [{
			"id": "` + id + `-policy",
			"context": { "greeting": { "required": true } },
			"tenets": [{
				"id": "t",
				"code": "` + code + `",
				"predicates": {"types": ["https://example.com/"]}
			}]
		}]
	}`))
	require.NoError(t, err)
	require.NotNil(t, set)
	return set
}

// TestVerifyPolicySetSlice checks that verifying several policy sets at once
// applies each set's common block, like verifying the sets one by one does.
func TestVerifyPolicySetSlice(t *testing.T) {
	t.Parallel()

	// Subject of testdata/link1.json, an unsigned in-toto statement.
	subject := &gointoto.ResourceDescriptor{
		Digest: map[string]string{"sha1": "856314ba21181a746186c24f1647d06e45048964"},
	}
	verify := func(t *testing.T, sets []*papi.PolicySet, policyIDs ...string) *papi.ResultSet {
		t.Helper()
		ampel, err := New()
		require.NoError(t, err)
		opts := NewVerificationOptions()
		opts.EnforceExpiration = false
		opts.AdmitUnverified = true
		opts.AttestationFiles = []string{"testdata/link1.json"}
		opts.Policies = policyIDs
		res, err := ampel.Verify(t.Context(), &opts, sets, subject)
		require.NoError(t, err)
		rs, ok := res.(*papi.ResultSet)
		require.True(t, ok, "a slice of sets yields a result set")
		return rs
	}
	passing := compileSet(t, "greets", "hi", "context.greeting == 'hi'")
	failing := compileSet(t, "frowns", "hi", "context.greeting == 'bye'")

	t.Run("single-set-keeps-common-context", func(t *testing.T) {
		t.Parallel()
		rs := verify(t, []*papi.PolicySet{passing})
		require.Equal(t, papi.StatusPASS, rs.GetStatus())
		require.Equal(t, "greets", rs.GetPolicySet().GetId(), "a single set returns its own result set")
		require.Len(t, rs.GetResults(), 1)
	})

	t.Run("all-sets-must-pass", func(t *testing.T) {
		t.Parallel()
		rs := verify(t, []*papi.PolicySet{passing, failing})
		require.Equal(t, papi.StatusFAIL, rs.GetStatus())
		require.Len(t, rs.GetResults(), 2, "results of every set are merged")
		require.Equal(t, papi.StatusPASS, rs.GetResults()[0].GetStatus())
		require.Equal(t, papi.StatusFAIL, rs.GetResults()[1].GetStatus())
	})

	t.Run("policy-filter-applies", func(t *testing.T) {
		t.Parallel()
		rs := verify(t, []*papi.PolicySet{passing, failing}, "greets-policy")
		require.Equal(t, papi.StatusPASS, rs.GetStatus(), "the failing policy was filtered out")
		require.Len(t, rs.GetResults(), 1)
	})
}

func TestSelectPolicies(t *testing.T) {
	t.Parallel()
	set := compileSet(t, "s", "hi", "true")
	require.Same(t, set, selectPolicies(set, nil), "no filter returns the set itself")

	selected := selectPolicies(set, []string{"other"})
	require.NotSame(t, set, selected)
	require.Empty(t, selected.GetPolicies())
	require.Len(t, set.GetPolicies(), 1, "the original set is untouched")
	require.NotNil(t, selected.GetCommon(), "the common block is preserved")
}
