// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	papi "github.com/carabiner-dev/policy/api/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/evaluator"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

// chainRewritingImpl wraps the default implementation and makes every
// chain resolve to another subject, as a policy chaining to a different
// artifact would.
type chainRewritingImpl struct {
	AmpelVerifier
	effective *gointoto.ResourceDescriptor
}

func (c *chainRewritingImpl) chain(original attestation.Subject) []*papi.ChainedSubject {
	return []*papi.ChainedSubject{{
		Source: &gointoto.ResourceDescriptor{
			Name: original.GetName(), Uri: original.GetUri(), Digest: original.GetDigest(),
		},
		Destination: c.effective,
	}}
}

func (c *chainRewritingImpl) ProcessChainedSubjects(
	_ context.Context, _ *VerificationOptions, _ map[class.Class]evaluator.Evaluator, _ *collector.Agent,
	_ papi.ChainProvider, _ map[string]any, subject attestation.Subject, _ []attestation.Envelope,
) (attestation.Subject, []*papi.ChainedSubject, bool, error) {
	return c.effective, c.chain(subject), false, nil
}

func (c *chainRewritingImpl) ProcessPolicySetChainedSubjects(
	_ context.Context, _ *VerificationOptions, _ map[class.Class]evaluator.Evaluator, _ *collector.Agent,
	_ *papi.PolicySet, _ map[string]any, subject attestation.Subject, _ []attestation.Envelope,
) ([]attestation.Subject, []*papi.ChainedSubject, bool, error) {
	return []attestation.Subject{c.effective}, c.chain(subject), false, nil
}

// TestResultsRecordOriginalSubject guards against results recording the
// effective subject a chain resolved to instead of the subject under
// evaluation. The attestations of the results are about the original
// subject, so all three result types must carry it.
func TestResultsRecordOriginalSubject(t *testing.T) {
	t.Parallel()

	original := &gointoto.ResourceDescriptor{
		Name:   "original",
		Digest: map[string]string{"sha256": "0000000000000000000000000000000000000000000000000000000000000001"},
	}
	effective := &gointoto.ResourceDescriptor{
		Name:   "effective",
		Digest: map[string]string{"sha256": "0000000000000000000000000000000000000000000000000000000000000002"},
	}

	policy := &papi.Policy{
		Id:     "pass",
		Meta:   &papi.Meta{},
		Tenets: []*papi.Tenet{{Id: "t1", Code: "true"}},
	}
	group := &papi.PolicyGroup{
		Id:   "group",
		Meta: &papi.PolicyGroupMeta{},
		Blocks: []*papi.PolicyBlock{
			{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{policy}},
		},
	}
	set := &papi.PolicySet{
		Id:       "set",
		Meta:     &papi.PolicySetMeta{},
		Policies: []*papi.Policy{policy},
		Groups:   []*papi.PolicyGroup{group},
	}

	newAmpel := func(t *testing.T) (*Ampel, *VerificationOptions) {
		t.Helper()
		ampel, err := New()
		require.NoError(t, err)
		ampel.impl = &chainRewritingImpl{AmpelVerifier: ampel.impl, effective: effective}
		return ampel, &VerificationOptions{
			EvaluatorOptions:    options.Default,
			DefaultEvaluator:    DefaultVerificationOptions.DefaultEvaluator,
			AllowEmptySetChains: true,
		}
	}

	requireOriginal := func(t *testing.T, what string, subject *gointoto.ResourceDescriptor) {
		t.Helper()
		require.Equal(t, original.GetDigest(), subject.GetDigest(), "%s records the effective subject instead of the original", what)
	}

	t.Run("policy", func(t *testing.T) {
		t.Parallel()
		ampel, opts := newAmpel(t)
		res, err := ampel.VerifySubjectWithPolicy(context.Background(), opts, policy, original)
		require.NoError(t, err)
		require.NotEmpty(t, res.GetChain(), "the chain must have run for the test to be meaningful")
		requireOriginal(t, "result", res.GetSubject())
	})

	t.Run("group", func(t *testing.T) {
		t.Parallel()
		ampel, opts := newAmpel(t)
		res, err := ampel.VerifySubjectWithPolicyGroup(context.Background(), opts, group, original)
		require.NoError(t, err)
		require.NotEmpty(t, res.GetChain(), "the chain must have run for the test to be meaningful")
		requireOriginal(t, "result group", res.GetSubject())
	})

	t.Run("set", func(t *testing.T) {
		t.Parallel()
		ampel, opts := newAmpel(t)
		res, err := ampel.VerifySubjectWithPolicySet(context.Background(), opts, set, original)
		require.NoError(t, err)
		require.NotEmpty(t, res.GetResults())
		require.NotEmpty(t, res.GetGroups())
		requireOriginal(t, "result set", res.GetSubject())
	})
}
