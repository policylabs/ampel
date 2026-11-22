// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"testing"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/ampel/pkg/evaluator"
	"github.com/policylabs/ampel/pkg/evaluator/class"
	eoptions "github.com/policylabs/ampel/pkg/evaluator/options"
)

// TestChainReachesTenets proves a policy's tenets see the chain the policy
// followed: the hop's type, source, destination and the predicate it was
// read from, so the tenet can compare what it finds at the end of the chain
// with what the chain was read from.
func TestChainReachesTenets(t *testing.T) {
	t.Parallel()
	opts := whenTestOptions()
	opts.AttestationFiles = []string{"testdata/wtf-frontend.spdx.json", "testdata/link1.json"}
	opts.AdmitUnverified = true
	subject := &gointoto.ResourceDescriptor{
		Name:   "test",
		Digest: map[string]string{"sha256": "851074691728c479a4c83628de8310eaca792cc7"},
	}
	link := &papi.ChainLink{Source: &papi.ChainLink_Predicate{Predicate: &papi.ChainedPredicate{
		Type:     "https://spdx.dev/Document",
		Selector: "'sha1:856314ba21181a746186c24f1647d06e45048964'",
	}}}
	for _, tc := range []struct {
		name   string
		code   string
		status string
	}{
		{"sees-the-hop", `size(chain) == 1 && chain[0].type == "https://spdx.dev/Document"`, papi.StatusPASS},
		{"sees-the-ends", `chain[0].source.digest.sha256 == "851074691728c479a4c83628de8310eaca792cc7" && chain[0].destination.digest.sha1 == "856314ba21181a746186c24f1647d06e45048964"`, papi.StatusPASS},
		{"reads-the-hop-predicate", `chain[0].predicate.data.spdxVersion == "SPDX-2.3" && chain[0].predicate.predicate_type == "https://spdx.dev/Document"`, papi.StatusPASS},
		{"compares-across-the-hop", `chain[0].predicate.data.spdxVersion == "SPDX-9.9"`, papi.StatusFAIL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			policy := &papi.Policy{
				Id:         tc.name,
				Meta:       &papi.Meta{},
				Chain:      []*papi.ChainLink{link},
				Predicates: &papi.PredicateSpec{Types: []string{"https://example.com/"}},
				Tenets:     []*papi.Tenet{{Id: "t1", Code: tc.code}},
			}
			ampel, err := New()
			require.NoError(t, err)
			res, err := ampel.VerifySubjectWithPolicy(context.Background(), opts, policy, subject)
			require.NoError(t, err)
			require.Equal(t, tc.status, res.GetStatus(), res.GetEvalResults())
			require.Len(t, res.GetChain(), 1, "the result records the hop")
		})
	}

	// The condition sees the chain as well.
	policy := &papi.Policy{
		Id:         "when-sees-chain",
		Meta:       &papi.Meta{},
		Chain:      []*papi.ChainLink{link},
		Predicates: &papi.PredicateSpec{Types: []string{"https://example.com/"}},
		When:       &papi.When{Expression: `chain[0].predicate.data.spdxVersion == "SPDX-9.9"`},
		Tenets:     []*papi.Tenet{{Id: "t1", Code: "true"}},
	}
	ampel, err := New()
	require.NoError(t, err)
	res, err := ampel.VerifySubjectWithPolicy(context.Background(), opts, policy, subject)
	require.NoError(t, err)
	require.Equal(t, papi.StatusSKIP, res.GetStatus())
}

// TestSelectorSeesEarlierHops proves a chain's later selectors see the hops
// followed before them, so a second hop can branch on what the first read.
func TestSelectorSeesEarlierHops(t *testing.T) {
	t.Parallel()
	opts := whenTestOptions()
	opts.AttestationFiles = []string{"testdata/wtf-frontend.spdx.json", "testdata/link1.json", "testdata/link2.json"}
	opts.AdmitUnverified = true
	subject := &gointoto.ResourceDescriptor{
		Name:   "test",
		Digest: map[string]string{"sha256": "851074691728c479a4c83628de8310eaca792cc7"},
	}
	policy := &papi.Policy{
		Id:   "second-hop-reads-first",
		Meta: &papi.Meta{},
		Chain: []*papi.ChainLink{
			{Source: &papi.ChainLink_Predicate{Predicate: &papi.ChainedPredicate{
				Type:     "https://spdx.dev/Document",
				Selector: "'sha1:856314ba21181a746186c24f1647d06e45048964'",
			}}},
			{Source: &papi.ChainLink_Predicate{Predicate: &papi.ChainedPredicate{
				Type: "https://example.com/",
				// Branches on the first hop: the SPDX document it was read from.
				Selector: `chain[0].predicate.data.spdxVersion == "SPDX-2.3" ? "sha1:93836eee21527f010b77faa3379ccba2f3dbc1b3" : "sha1:0000000000000000000000000000000000000000"`,
			}}},
		},
		Predicates: &papi.PredicateSpec{Types: []string{"https://example.com/"}},
		Tenets: []*papi.Tenet{{
			Id:   "t1",
			Code: `size(chain) == 2 && chain[1].source.digest.sha1 == "856314ba21181a746186c24f1647d06e45048964" && subject.digest.sha1 == "93836eee21527f010b77faa3379ccba2f3dbc1b3"`,
		}},
	}
	ampel, err := New()
	require.NoError(t, err)
	res, err := ampel.VerifySubjectWithPolicy(context.Background(), opts, policy, subject)
	require.NoError(t, err)
	require.Equal(t, papi.StatusPASS, res.GetStatus(), res.GetEvalResults())
	require.Len(t, res.GetChain(), 2)
}

// hopEnvelope wraps a parsed attestation to give it the verification a test
// needs: the signer identities of a verified signature, or none at all.
type hopEnvelope struct {
	attestation.Envelope
	ver attestation.Verification
}

func (he *hopEnvelope) GetVerification() attestation.Verification { return he.ver }
func (he *hopEnvelope) Verify(...any) error                       { return nil }

// TestChainHopAdmission proves the attestation a chain hop reads goes through
// the same admission gates as any other evidence: its signature must verify
// and, when signer identities are pinned, its signer must match one of them.
// Unverified attestations are only admitted when the caller passed them
// explicitly, opted in and no identity is pinned.
func TestChainHopAdmission(t *testing.T) {
	t.Parallel()
	di := &defaultIplementation{}
	def, err := (&evaluator.Factory{}).Get(&eoptions.Default, DefaultVerificationOptions.DefaultEvaluator)
	require.NoError(t, err)
	evaluators := map[class.Class]evaluator.Evaluator{
		defaultEvaluatorClass: def,
		DefaultVerificationOptions.DefaultEvaluator.BaseClass(): def,
	}
	subject := &gointoto.ResourceDescriptor{
		Name:   "test",
		Digest: map[string]string{"sha256": "851074691728c479a4c83628de8310eaca792cc7"},
	}

	signer := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{
		Issuer: "https://example.com", Identity: "joe@example.com",
	}}
	other := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{
		Issuer: "https://example.com", Identity: "mallory@example.com",
	}}
	signed := &sapi.Verification{Signature: &sapi.SignatureVerification{
		Verified: true, Identities: []*sapi.Identity{signer},
	}}

	for _, tc := range []struct {
		name      string
		ver       attestation.Verification // verification of the hop's attestation, nil when unsigned
		linkIDs   []*sapi.Identity         // identities pinned on the chain link
		policyIDs []*sapi.Identity         // identities the link falls back to
		optIDs    []string                 // identities pinned in the options
		admit     bool                     // AdmitUnverified
		explicit  bool                     // the attestation was passed explicitly
		mustFail  bool
		matched   int // identities recorded on the hop
	}{
		// Verified attestations.
		{name: "verified-no-identities", ver: signed},
		{name: "verified-link-identity-matches", ver: signed, linkIDs: []*sapi.Identity{signer}, matched: 1},
		{name: "verified-policy-identity-matches", ver: signed, policyIDs: []*sapi.Identity{signer}, matched: 1},
		{name: "verified-options-identity-matches", ver: signed, optIDs: []string{signer.Spec()}, matched: 1},
		{name: "verified-link-identity-mismatch", ver: signed, linkIDs: []*sapi.Identity{other}, mustFail: true},
		{name: "verified-policy-identity-mismatch", ver: signed, policyIDs: []*sapi.Identity{other}, mustFail: true},
		// The link's identities replace the policy's.
		{name: "link-identity-overrides-policy", ver: signed, linkIDs: []*sapi.Identity{other}, policyIDs: []*sapi.Identity{signer}, mustFail: true},

		// Unverified attestations.
		{name: "unsigned-rejected", mustFail: true},
		{name: "unsigned-explicit-without-opt-in", explicit: true, mustFail: true},
		// Evidence the caller did not pass (a collector's) is never admitted unverified.
		{name: "unsigned-opt-in-not-explicit", admit: true, mustFail: true},
		{name: "unsigned-opt-in-explicit", admit: true, explicit: true},
		// Pinned identities always require a verified signature.
		{name: "unsigned-opt-in-explicit-with-identity", admit: true, explicit: true, linkIDs: []*sapi.Identity{signer}, mustFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultVerificationOptions
			opts.AttestationFiles = []string{"testdata/wtf-frontend.spdx.json"}
			opts.AdmitUnverified = tc.admit
			parsed, err := di.ParseAttestations(t.Context(), &opts, subject)
			require.NoError(t, err)
			require.Len(t, parsed, 1)
			opts.IdentityStrings = tc.optIDs

			attestations := []attestation.Envelope{&hopEnvelope{Envelope: parsed[0], ver: tc.ver}}
			ctx := t.Context()
			if tc.explicit {
				ctx = withExplicitEvidence(ctx, attestations)
			}

			links := []*papi.ChainLink{{Source: &papi.ChainLink_Predicate{Predicate: &papi.ChainedPredicate{
				Type:       "https://spdx.dev/Document",
				Selector:   "'sha1:856314ba21181a746186c24f1647d06e45048964'",
				Identities: tc.linkIDs,
			}}}}

			subjects, hops, failed, err := di.evaluateChain(
				ctx, &opts, evaluators, nil, links, nil, subject, attestations, tc.policyIDs, "",
			)
			if tc.mustFail {
				require.ErrorContains(t, err, "unable to validate chained attestation identity")
				require.True(t, failed, "a rejected hop attestation is a policy failure")
				require.Empty(t, subjects)
				return
			}
			require.NoError(t, err)
			require.False(t, failed)
			require.Len(t, subjects, 1)
			require.Len(t, hops, 1)
			require.Len(t, hops[0].Record.GetLink().GetIdentities(), tc.matched)
		})
	}
}
