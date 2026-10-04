// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"testing"

	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/policy"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"

	acontext "github.com/policylabs/ampel/pkg/context"
	"github.com/policylabs/ampel/pkg/verifier"
)

// TestIdentityContextSourceRepo verifies a real GitHub Actions keyless bundle
// through the full ampel.Verify path. The policy (loaded from a file) bakes in
// the workflow issuer and binds the origin repo matcher to a context value with
// from_context; the verifier supplies the repo at runtime. Resolution happens
// before CheckIdentities, AND-ed inside the identity, so it fails closed. Hits
// the sigstore trust root over TUF (network).
func TestIdentityContextSourceRepo(t *testing.T) {
	envs, err := (&bundle.Parser{}).ParseFile("testdata/github-actions-bundle.json")
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	// Subject must carry the bundle digest: GatherAttestations filters by subject
	// before the identity check.
	subjects := env.GetStatement().GetSubjects()
	require.NotEmpty(t, subjects)
	subject := subjects[0]

	set, _, _, err := policy.NewCompiler().CompileLocation("testdata/identity-context-source-repo.json")
	require.NoError(t, err)
	require.NotNil(t, set)

	// verify runs ampel.Verify with the given -x context values (nil => unset).
	verify := func(t *testing.T, ctxVals []string) (papi.Results, error) {
		t.Helper()
		// New() yields a Collector returning ErrNoFetcherConfigured (handled);
		// the bundle survives via opts.Attestations.
		ampel, err := verifier.New()
		require.NoError(t, err)

		opts := verifier.NewVerificationOptions()
		opts.EnforceExpiration = false
		opts.Attestations = []attestation.Envelope{env}
		if ctxVals != nil {
			l := acontext.StringMapList(ctxVals)
			opts.ContextProviders = []acontext.Provider{&l}
		}
		return ampel.Verify(t.Context(), &opts, set, subject)
	}

	// Correct repo: admitted, tenet passes, PASS.
	t.Run("correct-repo", func(t *testing.T) {
		res, err := verify(t, []string{"source_repo:https://github.com/sigstore/sigstore-js"})
		require.NoError(t, err)
		require.Equal(t, papi.StatusPASS, res.GetStatus())
	})

	// Wrong repo: nothing admitted, FAIL — specifically at identity validation,
	// not the tenet.
	t.Run("wrong-repo", func(t *testing.T) {
		res, err := verify(t, []string{"source_repo:https://github.com/evil/repo"})
		require.NoError(t, err)
		require.Equal(t, papi.StatusFAIL, res.GetStatus())

		rs, ok := res.(*papi.ResultSet)
		require.True(t, ok)
		var sawIdentityFailure bool
		for _, r := range rs.GetResults() {
			for _, er := range r.GetEvalResults() {
				if er.GetError().GetMessage() == "attestation identity validation failed" {
					sawIdentityFailure = true
				}
			}
		}
		require.True(t, sawIdentityFailure, "wrong repo must fail at identity validation, not the tenet")
	})

	// Missing required source_repo: fail closed via context-assembly error.
	t.Run("missing-repo", func(t *testing.T) {
		_, err := verify(t, nil)
		require.Error(t, err)
	})
}
