// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"sync"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/collector/predicate/generic"
	papi "github.com/carabiner-dev/policy/api/v1"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/key"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

// fakeKey is a no-op key.PublicKeyProvider; GatherAttestations only appends it
// to the shared collector key set, so its contents are irrelevant here.
type fakeKey struct{}

func (fakeKey) PublicKey() (*key.Public, error) { return &key.Public{}, nil }

// fakePredicate is a minimal attestation.Predicate backed by the generic
// predicate so SetVerification/GetVerification behave like a real one.
type sharedFakeStatement struct {
	pred attestation.Predicate
}

func (s *sharedFakeStatement) GetSubjects() []attestation.Subject          { return nil }
func (s *sharedFakeStatement) GetPredicate() attestation.Predicate         { return s.pred }
func (s *sharedFakeStatement) GetPredicateType() attestation.PredicateType { return "test/v1" }
func (s *sharedFakeStatement) GetType() string                             { return "https://in-toto.io/Statement/v1" }

func (s *sharedFakeStatement) GetVerification() attestation.Verification {
	return s.pred.GetVerification()
}

// sharedFakeEnvelope emulates a sigstore bundle envelope: Verify() resolves the
// concrete signer identity from the (mocked) signing material exactly once and
// caches it on the predicate, returning early on subsequent calls. This is the
// behavior in collector/envelope/bundle that, combined with sharing envelopes
// across policy evaluations, exposes the issue #298 corruption.
type sharedFakeEnvelope struct {
	stmt   *sharedFakeStatement
	signer *sapi.Identity
}

func newSharedFakeEnvelope(signer *sapi.Identity) *sharedFakeEnvelope {
	return &sharedFakeEnvelope{
		stmt:   &sharedFakeStatement{pred: &generic.Predicate{Type: "test/v1"}},
		signer: signer,
	}
}

func (e *sharedFakeEnvelope) GetStatement() attestation.Statement     { return e.stmt }
func (e *sharedFakeEnvelope) GetPredicate() attestation.Predicate     { return e.stmt.pred }
func (e *sharedFakeEnvelope) GetSignatures() []attestation.Signature  { return nil }
func (e *sharedFakeEnvelope) GetCertificate() attestation.Certificate { return nil }
func (e *sharedFakeEnvelope) GetVerification() attestation.Verification {
	return e.stmt.pred.GetVerification()
}

func (e *sharedFakeEnvelope) Verify(_ ...any) error {
	// Emulate the bundle envelope cache: the concrete signer identity is
	// resolved once from the signing material and never recomputed.
	if e.GetVerification() != nil {
		return nil
	}
	e.stmt.pred.SetVerification(&sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Verified:   true,
			Identities: []*sapi.Identity{e.signer},
		},
	})
	return nil
}

// concreteSigner is the identity actually carried by the signing material.
func concreteSigner() *sapi.Identity {
	return &sapi.Identity{
		Sigstore: &sapi.IdentitySigstore{
			Issuer:   "https://token.actions.githubusercontent.com",
			Identity: "https://github.com/org/repo/.github/workflows/build.yml@refs/tags/v1.0.0",
		},
	}
}

// policyIdentity binds to the signer through matchers (not concrete values),
// mirroring how real policies pin builders. The matched identity restamped by
// the old FilterAttestations therefore carries empty Issuer/Identity, which is
// what corrupts later identity checks.
func policyIdentity() *sapi.Identity {
	return &sapi.Identity{
		Id: "wrangle-builder",
		Sigstore: &sapi.IdentitySigstore{
			IssuerMatch: &sapi.StringMatcher{
				Kind: &sapi.StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"},
			},
			IdentityMatch: &sapi.StringMatcher{
				Kind: &sapi.StringMatcher_Regex{
					Regex: "https://github.com/org/repo/.github/workflows/build.yml@.+",
				},
			},
		},
	}
}

// TestFilterAttestationsDoesNotMutateSharedEnvelope asserts the core invariant
// behind issue #298: FilterAttestations must not overwrite the signer-identity
// verification cached on the (shared) envelope. The old implementation called
// pred.SetVerification with the per-policy matched identities, poisoning the
// cache for every other policy that shares the same envelope.
func TestFilterAttestationsDoesNotMutateSharedEnvelope(t *testing.T) {
	t.Parallel()
	di := &defaultIplementation{}
	opts := &VerificationOptions{}
	subject := &gointoto.ResourceDescriptor{
		Digest: map[string]string{"sha256": "aaaa0000000000000000000000000000000000000000000000000000000000aa"},
	}

	env := newSharedFakeEnvelope(concreteSigner())
	envs := []attestation.Envelope{env}
	ids := []admission{{admitted: true, verified: true, identities: []*sapi.Identity{policyIdentity()}}}

	// Establish the signer-identity verification as Verify() would.
	require.NoError(t, env.Verify())
	before := env.GetVerification()
	require.NotNil(t, before)
	require.True(t, before.MatchesIdentity(policyIdentity()),
		"sanity: signer identity must match the policy identity before filtering")

	if _, err := di.FilterAttestations(opts, subject, envs, ids); err != nil {
		t.Fatalf("FilterAttestations: %v", err)
	}

	// The shared envelope's verification must still be the signer identity.
	require.True(t, env.GetVerification().MatchesIdentity(policyIdentity()),
		"FilterAttestations must not overwrite the shared envelope's signer identity")
}

// TestCheckIdentitiesWorkerIndependentSharing reproduces the issue #298 symptom
// at the function level: two policies sharing the same envelope must both admit
// the attestation. The first policy's FilterAttestations call used to corrupt
// the shared verification so the second CheckIdentities spuriously failed.
func TestCheckIdentitiesWorkerIndependentSharing(t *testing.T) {
	t.Parallel()
	di := &defaultIplementation{}
	opts := &VerificationOptions{}
	subject := &gointoto.ResourceDescriptor{
		Digest: map[string]string{"sha256": "aaaa0000000000000000000000000000000000000000000000000000000000aa"},
	}
	ctx := context.Background()

	env := newSharedFakeEnvelope(concreteSigner())
	envs := []attestation.Envelope{env}

	// Policy A: admit, then filter (this is where the shared mutation happened).
	allowA, idsA, errsA, err := di.CheckIdentities(ctx, opts, []*sapi.Identity{policyIdentity()}, envs)
	require.NoError(t, err)
	require.True(t, allowA, "policy A must admit the attestation: %v", errsA)
	if _, err := di.FilterAttestations(opts, subject, envs, idsA); err != nil {
		t.Fatalf("FilterAttestations: %v", err)
	}

	// Policy B shares the same envelope. It must still admit the attestation,
	// independent of whether policy A ran first.
	allowB, _, errsB, err := di.CheckIdentities(ctx, opts, []*sapi.Identity{policyIdentity()}, envs)
	require.NoError(t, err)
	require.True(t, allowB, "policy B must still admit the attestation after policy A filtered: %v", errsB)
}

// TestCheckIdentitiesRejectsWrongIdentity locks in the fail-closed property:
// an attestation whose signer does not match the policy identity must be
// rejected, and that rejection must survive a prior policy filtering the shared
// envelope (i.e. the shared-state fix must not accidentally admit a wrong
// signer).
func TestCheckIdentitiesRejectsWrongIdentity(t *testing.T) {
	t.Parallel()
	di := &defaultIplementation{}
	opts := &VerificationOptions{}
	subject := &gointoto.ResourceDescriptor{
		Digest: map[string]string{"sha256": "aaaa0000000000000000000000000000000000000000000000000000000000aa"},
	}
	ctx := context.Background()

	env := newSharedFakeEnvelope(concreteSigner())
	envs := []attestation.Envelope{env}

	// A correctly-matching policy admits and filters the shared envelope first.
	allow, ids, _, err := di.CheckIdentities(ctx, opts, []*sapi.Identity{policyIdentity()}, envs)
	require.NoError(t, err)
	require.True(t, allow)
	if _, err := di.FilterAttestations(opts, subject, envs, ids); err != nil {
		t.Fatalf("FilterAttestations: %v", err)
	}

	// A policy binding a different identity must NOT be admitted.
	wrong := &sapi.Identity{
		Id: "wrong-builder",
		Sigstore: &sapi.IdentitySigstore{
			IssuerMatch: &sapi.StringMatcher{
				Kind: &sapi.StringMatcher_Exact{Exact: "https://token.actions.githubusercontent.com"},
			},
			IdentityMatch: &sapi.StringMatcher{
				Kind: &sapi.StringMatcher_Exact{Exact: "https://github.com/org/repo/.github/workflows/other.yml@refs/tags/v1.0.0"},
			},
		},
	}
	allowWrong, _, _, err := di.CheckIdentities(ctx, opts, []*sapi.Identity{wrong}, envs)
	require.NoError(t, err)
	require.False(t, allowWrong, "an attestation signed by a non-matching identity must be rejected")
}

// TestCheckIdentitiesConcurrentSharing exercises the concurrent path: many
// policies verifying the same shared envelopes at once. It publishes the
// per-run lock on the context exactly as VerifySubjectWithPolicySet does. Run
// with -race to catch concurrent reads/writes of the shared verification.
func TestCheckIdentitiesConcurrentSharing(t *testing.T) {
	t.Parallel()
	di := &defaultIplementation{}
	opts := &VerificationOptions{}
	subject := &gointoto.ResourceDescriptor{
		Digest: map[string]string{"sha256": "aaaa0000000000000000000000000000000000000000000000000000000000aa"},
	}
	ctx := context.WithValue(context.Background(), sharedEvidenceLockKey{}, &sync.Mutex{})

	env := newSharedFakeEnvelope(concreteSigner())
	envs := []attestation.Envelope{env}

	var wg sync.WaitGroup
	results := make([]bool, 16)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			allow, ids, _, err := di.CheckIdentities(ctx, opts, []*sapi.Identity{policyIdentity()}, envs)
			if err != nil {
				return
			}
			if _, err := di.FilterAttestations(opts, subject, envs, ids); err != nil {
				t.Errorf("FilterAttestations: %v", err)
				return
			}
			results[idx] = allow
		}(i)
	}
	wg.Wait()

	for i, allow := range results {
		require.True(t, allow, "goroutine %d must admit the shared attestation", i)
	}
}

// TestGatherAttestationsConcurrentKeyDistribution exercises the shared collector
// agent: the per-policy GatherAttestations distributes verification keys into
// the one agent shared across a run's concurrent policies/groups. AddKeys is not
// internally synchronized, so without the per-run evidence lock this races on
// the agent's key slice. It publishes the lock as VerifySubjectWithPolicySet
// does; run with -race.
func TestGatherAttestationsConcurrentKeyDistribution(t *testing.T) {
	t.Parallel()
	di := &defaultIplementation{}
	agent, err := collector.New()
	require.NoError(t, err)

	opts := &VerificationOptions{Keys: []key.PublicKeyProvider{fakeKey{}, fakeKey{}}}
	subject := &gointoto.ResourceDescriptor{
		Digest: map[string]string{"sha256": "aaaa0000000000000000000000000000000000000000000000000000000000aa"},
	}
	policy := &papi.Policy{Id: "p"}
	ctx := context.WithValue(context.Background(), sharedEvidenceLockKey{}, &sync.Mutex{})

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// No fetcher repos are configured, so this returns no envelopes; the
			// point is the AddKeys call on the shared agent before the fetch.
			if _, err := di.GatherAttestations(ctx, opts, agent, policy, subject, nil); err != nil {
				t.Errorf("GatherAttestations: %v", err)
			}
		}()
	}
	wg.Wait()
}
