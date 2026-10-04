// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"testing"

	gointoto "github.com/in-toto/attestation/go/v1"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

// whenTestOptions mirrors the options the group tests use: no expiration
// checks and no evidence, so policies with constant tenets can run.
func whenTestOptions() *VerificationOptions {
	return &VerificationOptions{
		EvaluatorOptions:    options.Default,
		DefaultEvaluator:    DefaultVerificationOptions.DefaultEvaluator,
		EnforceExpiration:   false,
		AllowEmptySetChains: true,
	}
}

func whenTestSubject() *gointoto.ResourceDescriptor {
	return &gointoto.ResourceDescriptor{
		Name:   "test-subject",
		Digest: map[string]string{"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
	}
}

// gatedPolicy returns a passing policy gated by the given expression.
func gatedPolicy(id, expression string) *papi.Policy {
	return &papi.Policy{
		Id:     id,
		Meta:   &papi.Meta{},
		When:   &papi.When{Expression: expression},
		Tenets: []*papi.Tenet{{Id: "t1", Code: "true", Assessment: &papi.Assessment{Message: "ran"}}},
	}
}

// envContext declares the "env" string context value with a burned-in value.
func envContext(value string) map[string]*papi.ContextVal {
	return map[string]*papi.ContextVal{
		"env": {Type: papi.ContextTypeString, Value: structpb.NewStringValue(value)},
	}
}

func TestWhenPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		policy       *papi.Policy
		expectStatus string
		expectErr    string
	}{
		{"no-condition-runs", &papi.Policy{Id: "plain", Meta: &papi.Meta{}, Tenets: []*papi.Tenet{{Id: "t1", Code: "true"}}}, papi.StatusPASS, ""},
		{"empty-condition-runs", gatedPolicy("empty", "  "), papi.StatusPASS, ""},
		{"true-runs", gatedPolicy("yes", "true"), papi.StatusPASS, ""},
		{"false-skips", gatedPolicy("no", "false"), papi.StatusSKIP, ""},
		{"reads-subject", gatedPolicy("subj", "subject.name == 'test-subject'"), papi.StatusPASS, ""},
		{"reads-own-context", func() *papi.Policy {
			p := gatedPolicy("ctx", "context.env == 'prod'")
			p.Context = envContext("prod")
			return p
		}(), papi.StatusPASS, ""},
		{"context-false-skips", func() *papi.Policy {
			p := gatedPolicy("ctx-no", "context.env == 'prod'")
			p.Context = envContext("dev")
			return p
		}(), papi.StatusSKIP, ""},
		{"non-boolean-errors", gatedPolicy("str", "'yes'"), "", "must yield a boolean"},
		{"undeclared-context-errors", gatedPolicy("undecl", "context.nope == 'x'"), "", "condition"},
		{"unknown-runtime-errors", &papi.Policy{
			Id: "rt", Meta: &papi.Meta{}, When: &papi.When{Expression: "true", Runtime: "cel@v99"},
			Tenets: []*papi.Tenet{{Id: "t1", Code: "true"}},
		}, "", "condition"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ampel, err := New()
			require.NoError(t, err)
			res, err := ampel.VerifySubjectWithPolicy(context.Background(), whenTestOptions(), tc.policy, whenTestSubject())
			if tc.expectErr != "" {
				require.ErrorContains(t, err, tc.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectStatus, res.GetStatus())
			if tc.expectStatus == papi.StatusSKIP {
				require.Len(t, res.GetEvalResults(), 1, "the skip is recorded as a single evaluation result")
				require.Equal(t, "when", res.GetEvalResults()[0].GetId())
				require.Equal(t, papi.StatusSKIP, res.GetEvalResults()[0].GetStatus())
				require.Contains(t, res.GetEvalResults()[0].GetAssessment().GetMessage(), "is false")
				require.Equal(t, tc.policy.GetId(), res.GetPolicy().GetId())
			}
		})
	}
}

func TestWhenPolicySet(t *testing.T) {
	t.Parallel()
	ampel, err := New()
	require.NoError(t, err)

	t.Run("common-context-gates-policies", func(t *testing.T) {
		t.Parallel()
		set := &papi.PolicySet{
			Id:     "set",
			Common: &papi.PolicySetCommon{Context: envContext("prod")},
			Policies: []*papi.Policy{
				gatedPolicy("prod-only", "context.env == 'prod'"),
				gatedPolicy("dev-only", "context.env == 'dev'"),
			},
		}
		rs, err := ampel.VerifySubjectWithPolicySet(context.Background(), whenTestOptions(), set, whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusPASS, rs.GetStatus(), "skipped policies do not count against the set")
		require.Len(t, rs.GetResults(), 2)
		require.Equal(t, papi.StatusPASS, rs.GetResults()[0].GetStatus())
		require.Equal(t, papi.StatusSKIP, rs.GetResults()[1].GetStatus())
	})

	t.Run("all-policies-skipped-skips-the-set", func(t *testing.T) {
		t.Parallel()
		set := &papi.PolicySet{Id: "set", Policies: []*papi.Policy{gatedPolicy("a", "false"), gatedPolicy("b", "false")}}
		rs, err := ampel.VerifySubjectWithPolicySet(context.Background(), whenTestOptions(), set, whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusSKIP, rs.GetStatus(), "nothing was verified")
	})

	t.Run("merged-sets-follow-the-same-rules", func(t *testing.T) {
		t.Parallel()
		skipped := &papi.PolicySet{Id: "skipped", Policies: []*papi.Policy{gatedPolicy("a", "false")}}
		passing := &papi.PolicySet{Id: "passing", Policies: []*papi.Policy{gatedPolicy("b", "true")}}
		res, err := ampel.Verify(context.Background(), whenTestOptions(), []*papi.PolicySet{skipped, passing}, whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusPASS, res.GetStatus())
		res, err = ampel.Verify(context.Background(), whenTestOptions(), []*papi.PolicySet{skipped, skipped}, whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusSKIP, res.GetStatus())
	})

	t.Run("failing-applicable-policy-still-fails", func(t *testing.T) {
		t.Parallel()
		failing := gatedPolicy("fails", "true")
		failing.Tenets = []*papi.Tenet{{Id: "t1", Code: "false", Error: &papi.Error{Message: "nope"}}}
		set := &papi.PolicySet{Id: "set", Policies: []*papi.Policy{gatedPolicy("skipped", "false"), failing}}
		rs, err := ampel.VerifySubjectWithPolicySet(context.Background(), whenTestOptions(), set, whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusFAIL, rs.GetStatus())
	})
}

func TestWhenBlocks(t *testing.T) {
	t.Parallel()
	ampel, err := New()
	require.NoError(t, err)
	group := func(blocks ...*papi.PolicyBlock) *papi.PolicyGroup {
		return &papi.PolicyGroup{
			Id:     "grp",
			Meta:   &papi.PolicyGroupMeta{},
			Common: &papi.PolicySetCommon{Context: envContext("prod")},
			Blocks: blocks,
		}
	}
	block := func(id, when string, policies ...*papi.Policy) *papi.PolicyBlock {
		b := &papi.PolicyBlock{Id: id, Meta: &papi.PolicyBlockMeta{}, Policies: policies}
		if when != "" {
			b.When = &papi.When{Expression: when}
		}
		return b
	}

	t.Run("block-condition-skips-its-policies", func(t *testing.T) {
		t.Parallel()
		res, err := ampel.VerifySubjectWithPolicyGroup(context.Background(), whenTestOptions(),
			group(
				block("dev", "context.env == 'dev'", gatedPolicy("never-runs", "true")),
				block("prod", "context.env == 'prod'", gatedPolicy("runs", "true")),
			), whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusPASS, res.GetStatus(), "a skipped block does not count against the group")
		require.Len(t, res.GetEvalResults(), 2)
		require.Equal(t, papi.StatusSKIP, res.GetEvalResults()[0].GetStatus())
		require.Empty(t, res.GetEvalResults()[0].GetResults(), "policies of a skipped block are not evaluated")
		require.Contains(t, res.GetEvalResults()[0].GetError().GetMessage(), "is false")
		require.Equal(t, papi.StatusPASS, res.GetEvalResults()[1].GetStatus())
	})

	t.Run("all-policies-skipped-skips-the-block", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []string{"", "AND", "OR"} {
			b := block("b", "", gatedPolicy("a", "false"), gatedPolicy("b", "false"))
			b.Meta.AssertMode = mode
			res, err := ampel.VerifySubjectWithPolicyGroup(context.Background(), whenTestOptions(), group(b), whenTestSubject())
			require.NoError(t, err)
			require.Equal(t, papi.StatusSKIP, res.GetEvalResults()[0].GetStatus(), "mode %q", mode)
			require.Equal(t, papi.StatusSKIP, res.GetStatus(), "a group whose blocks all skipped is skipped, mode %q", mode)
		}
	})

	t.Run("or-block-with-skips-and-a-pass-passes", func(t *testing.T) {
		t.Parallel()
		b := block("or", "", gatedPolicy("skipped", "false"), gatedPolicy("passes", "true"))
		b.Meta.AssertMode = "OR"
		res, err := ampel.VerifySubjectWithPolicyGroup(context.Background(), whenTestOptions(), group(b), whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusPASS, res.GetEvalResults()[0].GetStatus())
	})

	t.Run("explicit-and-block-with-passing-policies-passes", func(t *testing.T) {
		t.Parallel()
		// Regression: the AND check used to read as
		// (status == FAIL && mode == "") || mode == "AND", so any result
		// marked an explicitly AND block as failed.
		b := block("and-pass", "", gatedPolicy("a", "true"), gatedPolicy("b", "true"))
		b.Meta.AssertMode = "AND"
		res, err := ampel.VerifySubjectWithPolicyGroup(context.Background(), whenTestOptions(), group(b), whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusPASS, res.GetEvalResults()[0].GetStatus())
		require.Equal(t, papi.StatusPASS, res.GetStatus())
	})

	t.Run("and-block-with-skips-and-a-fail-fails", func(t *testing.T) {
		t.Parallel()
		failing := gatedPolicy("fails", "true")
		failing.Tenets = []*papi.Tenet{{Id: "t1", Code: "false", Error: &papi.Error{Message: "nope"}}}
		b := block("and", "", gatedPolicy("skipped", "false"), failing)
		b.Meta.AssertMode = "AND"
		res, err := ampel.VerifySubjectWithPolicyGroup(context.Background(), whenTestOptions(), group(b), whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusFAIL, res.GetEvalResults()[0].GetStatus())
		require.Equal(t, papi.StatusFAIL, res.GetStatus())
	})
}
