// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/policy"
	papi "github.com/policylabs/policy/api/v1"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/require"
)

// failureMessages collects the error messages of every failed evaluation in
// a result set, so tests can tell which gate stopped the evidence.
func failureMessages(t *testing.T, res papi.Results) []string {
	t.Helper()
	var results []*papi.Result
	switch r := res.(type) {
	case *papi.Result:
		results = []*papi.Result{r}
	case *papi.ResultSet:
		results = r.GetResults()
	default:
		t.Fatalf("unexpected results type %T", res)
	}
	var msgs []string
	for _, r := range results {
		for _, er := range r.GetEvalResults() {
			if er.GetError() != nil {
				msgs = append(msgs, er.GetError().GetMessage())
			}
		}
	}
	return msgs
}

// TestVerifyUnverifiedEvidence runs an unsigned (bare) statement through the
// full Verify path. Without an opt-in the evidence is rejected at the
// signature gate and the policy fails with ErrUnverifiedAttestations rather
// than a misleading "missing attestations". With AdmitUnverified, evidence
// passed through AttestationFiles is admitted, but never once the policy or
// the options pin signer identities.
func TestVerifyUnverifiedEvidence(t *testing.T) {
	t.Parallel()

	set, pcy, _, err := policy.NewCompiler().Compile([]byte(`{
		"id": "has-example",
		"tenets": [{
			"id": "t",
			"code": "size(predicates) > 0",
			"predicates": {"types": ["https://example.com/"]}
		}]
	}`))
	require.NoError(t, err)
	var target any = pcy
	if set != nil {
		target = set
	}
	require.NotNil(t, target)

	// Subject of testdata/link1.json, an unsigned in-toto statement.
	subject := &gointoto.ResourceDescriptor{
		Digest: map[string]string{"sha1": "856314ba21181a746186c24f1647d06e45048964"},
	}

	verify := func(t *testing.T, mutate func(*VerificationOptions)) papi.Results {
		t.Helper()
		ampel, err := New()
		require.NoError(t, err)
		opts := NewVerificationOptions()
		opts.EnforceExpiration = false
		opts.AttestationFiles = []string{"testdata/link1.json"}
		if mutate != nil {
			mutate(&opts)
		}
		res, err := ampel.Verify(t.Context(), &opts, target, subject)
		require.NoError(t, err)
		return res
	}

	t.Run("rejected-by-default", func(t *testing.T) {
		t.Parallel()
		res := verify(t, nil)
		require.Equal(t, papi.StatusFAIL, res.GetStatus())
		require.Contains(t, failureMessages(t, res), ErrUnverifiedAttestations.Error())
	})

	t.Run("admitted-when-opted-in", func(t *testing.T) {
		t.Parallel()
		res := verify(t, func(o *VerificationOptions) { o.AdmitUnverified = true })
		require.Equal(t, papi.StatusPASS, res.GetStatus())
	})

	t.Run("never-admitted-under-identity-constraint", func(t *testing.T) {
		t.Parallel()
		signer := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://example.com", Identity: "alice@example.com"}}
		res := verify(t, func(o *VerificationOptions) {
			o.AdmitUnverified = true
			o.IdentityStrings = []string{signer.Spec()}
		})
		require.Equal(t, papi.StatusFAIL, res.GetStatus())
		require.Contains(t, failureMessages(t, res), "attestation identity validation failed")
	})
}
