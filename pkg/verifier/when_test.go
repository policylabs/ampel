// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"testing"
	"time"

	gointoto "github.com/in-toto/attestation/go/v1"
	papi "github.com/policylabs/policy/api/v1"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/policylabs/ampel/pkg/evaluator/options"
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
		// The engine is always newer than v0.0.1, a release or a development build.
		{"reads-the-engine", gatedPolicy("engine-yes", "ampel.atLeast('v0.0.1')"), papi.StatusPASS, ""},
		{"engine-condition-false-skips", gatedPolicy("engine-no", "ampel.olderThan('v0.0.1')"), papi.StatusSKIP, ""},
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
				require.Len(t, res.GetEvalResults(), 1, "a skip with sound evidence records only the condition")
				require.Equal(t, "when", res.GetEvalResults()[0].GetId())
				require.Equal(t, papi.StatusSKIP, res.GetEvalResults()[0].GetStatus())
				require.Contains(t, res.GetEvalResults()[0].GetAssessment().GetMessage(), "is false")
				require.Equal(t, tc.policy.GetId(), res.GetPolicy().GetId())
			}
		})
	}
}

// A condition is decided after the evidence is collected, so it sees the
// subject the tenets would see, and a policy that does not apply skips even
// when collecting its evidence failed.
func TestWhenAfterEvidence(t *testing.T) {
	t.Parallel()
	const (
		original = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
		chained  = "cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b"
	)
	withEvidence := func() *VerificationOptions {
		o := whenTestOptions()
		o.AttestationFiles = []string{"testdata/wtf-frontend.spdx.json"}
		// The SPDX document the chains read is unsigned: admit it as
		// explicitly passed evidence. Pinned identities still reject it.
		o.AdmitUnverified = true
		return o
	}
	// chainedPolicy follows the SPDX document to a package digest.
	chainedPolicy := func(id, expression string) *papi.Policy {
		p := gatedPolicy(id, expression)
		p.Chain = []*papi.ChainLink{{Source: &papi.ChainLink_Predicate{Predicate: &papi.ChainedPredicate{
			Type: "https://spdx.dev/Document", Selector: `"sha256:` + chained + `"`,
		}}}}
		return p
	}
	// brokenChainPolicy has a link no attestation can satisfy.
	brokenChainPolicy := func(id, expression string) *papi.Policy {
		p := gatedPolicy(id, expression)
		p.Chain = []*papi.ChainLink{{Source: &papi.ChainLink_Predicate{Predicate: &papi.ChainedPredicate{
			Type: "https://example.com/nonexistent", Selector: `"sha256:` + chained + `"`,
		}}}}
		return p
	}
	// signedOnlyPolicy admits no unsigned evidence, which is all there is.
	signedOnlyPolicy := func(id, expression string) *papi.Policy {
		p := gatedPolicy(id, expression)
		p.Identities = []*sapi.Identity{{Sigstore: &sapi.IdentitySigstore{Issuer: "https://issuer.example", Identity: "someone@example.com"}}}
		return p
	}

	for _, tc := range []struct {
		name         string
		policy       *papi.Policy
		expectStatus string
		expectChain  int
		// setAside is what the failure recorded on a skip must say.
		setAside string
	}{
		{"sees-the-chained-subject", chainedPolicy("chained", "subject.digest.sha256 == '"+chained+"'"), papi.StatusPASS, 1, ""},
		{"original-subject-is-gone-after-the-chain", chainedPolicy("orig", "subject.digest.sha256 == '"+original+"'"), papi.StatusSKIP, 1, ""},
		{"broken-chain-fails-when-the-policy-applies", brokenChainPolicy("broken-applies", "true"), papi.StatusFAIL, 0, ""},
		{"broken-chain-skips-when-the-policy-does-not-apply", brokenChainPolicy("broken-skips", "false"), papi.StatusSKIP, 0, "no matching attestations"},
		{"rejected-evidence-fails-when-the-policy-applies", signedOnlyPolicy("ids-applies", "true"), papi.StatusFAIL, 0, ""},
		{"rejected-evidence-skips-when-the-policy-does-not-apply", signedOnlyPolicy("ids-skips", "false"), papi.StatusSKIP, 0, "identity validation failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ampel, err := New()
			require.NoError(t, err)
			res, err := ampel.VerifySubjectWithPolicy(context.Background(), withEvidence(), tc.policy, whenTestSubject())
			require.NoError(t, err)
			require.Equal(t, tc.expectStatus, res.GetStatus())
			require.Len(t, res.GetChain(), tc.expectChain, "the chain followed is recorded on every outcome")
			require.Equal(t, original, res.GetSubject().GetDigest()["sha256"], "the result is about the original subject")
			if tc.expectStatus == papi.StatusSKIP {
				require.Equal(t, "when", res.GetEvalResults()[0].GetId())
			}
			if tc.expectStatus == papi.StatusSKIP && tc.setAside != "" {
				// The failure the skip set aside is recorded after the
				// condition, skipped like it, with its message and guidance.
				require.Len(t, res.GetEvalResults(), 2)
				evidence := res.GetEvalResults()[1]
				require.Equal(t, "evidence", evidence.GetId())
				require.Equal(t, papi.StatusSKIP, evidence.GetStatus())
				require.Contains(t, evidence.GetAssessment().GetMessage(), tc.setAside)
				require.Contains(t, evidence.GetError().GetMessage(), tc.setAside)
				require.NotEmpty(t, evidence.GetError().GetGuidance())
			} else if tc.expectStatus == papi.StatusSKIP {
				require.Len(t, res.GetEvalResults(), 1, "nothing was set aside")
			}
		})
	}
}

// A condition sees the evidence the policy collected, so a policy can skip
// instead of failing when its evidence is absent.
func TestWhenSeesPredicates(t *testing.T) {
	t.Parallel()
	const spdx = "https://spdx.dev/Document"
	// The fixture is unsigned, so it has to be admitted to count as evidence.
	withEvidence := func() *VerificationOptions {
		o := whenTestOptions()
		o.AttestationFiles = []string{"testdata/wtf-frontend.spdx.json"}
		o.AdmitUnverified = true
		return o
	}
	typed := func(p *papi.Policy, types ...string) *papi.Policy {
		p.Predicates = &papi.PredicateSpec{Types: types}
		return p
	}

	for _, tc := range []struct {
		name         string
		policy       *papi.Policy
		opts         *VerificationOptions
		expectStatus string
	}{
		{"evidence-present-applies", gatedPolicy("some", "size(predicates) > 0"), withEvidence(), papi.StatusPASS},
		{"evidence-absent-skips", gatedPolicy("none", "size(predicates) > 0"), whenTestOptions(), papi.StatusSKIP},
		{"reads-the-predicate-type", gatedPolicy("type", "predicates.exists(p, p.predicate_type == '"+spdx+"')"), withEvidence(), papi.StatusPASS},
		{"first-predicate", gatedPolicy("first", "predicate.predicate_type == '"+spdx+"'"), withEvidence(), papi.StatusPASS},
		{"declared-types-narrow-the-evidence", typed(gatedPolicy("other", "size(predicates) > 0"), "https://example.com/other"), withEvidence(), papi.StatusSKIP},
		{"declared-type-present", typed(gatedPolicy("declared", "size(predicates) == 1"), spdx), withEvidence(), papi.StatusPASS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ampel, err := New()
			require.NoError(t, err)
			res, err := ampel.VerifySubjectWithPolicy(context.Background(), tc.opts, tc.policy, whenTestSubject())
			require.NoError(t, err)
			require.Equal(t, tc.expectStatus, res.GetStatus())
		})
	}

	t.Run("context-values-still-cannot-see-predicates", func(t *testing.T) {
		t.Parallel()
		// A dynamic context value is resolved before any evidence is read.
		expr := "size(predicates)"
		p := gatedPolicy("ctx", "true")
		p.Context = map[string]*papi.ContextVal{"count": {Type: papi.ContextTypeInt, Expression: &expr}}
		ampel, err := New()
		require.NoError(t, err)
		_, err = ampel.VerifySubjectWithPolicy(context.Background(), withEvidence(), p, whenTestSubject())
		require.ErrorContains(t, err, "context")
	})
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
		// Nothing verified at the root is a failure unless skips are allowed.
		res, err = ampel.Verify(context.Background(), whenTestOptions(), []*papi.PolicySet{skipped, skipped}, whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusFAIL, res.GetStatus())
		allowing := whenTestOptions()
		allowing.AllowSkip = true
		res, err = ampel.Verify(context.Background(), allowing, []*papi.PolicySet{skipped, skipped}, whenTestSubject())
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

// Verify stamps the run's start once, so every policy of a run reads the
// same ampel.started(), and the nested entry points honor a start the
// caller sets.
func TestEngineRunStart(t *testing.T) {
	t.Parallel()
	startedPolicy := func(id string) *papi.Policy {
		return &papi.Policy{
			Id:   id,
			Meta: &papi.Meta{},
			// Outputs are evaluated lazily, so the code reads the one it records.
			Tenets: []*papi.Tenet{{
				Id:      "t1",
				Outputs: map[string]*papi.Output{"started": {Code: "string(ampel.started())"}},
				Code:    "outputs.started != '' && ampel.started() >= timestamp(context.t0)",
			}},
			Context: map[string]*papi.ContextVal{"t0": {Type: papi.ContextTypeString, Value: structpb.NewStringValue(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))}},
		}
	}
	startedOutput := func(t *testing.T, r *papi.Result) string {
		t.Helper()
		require.Equal(t, papi.StatusPASS, r.GetStatus())
		out := r.GetEvalResults()[0].GetOutput().AsMap()["started"]
		s, ok := out.(string)
		require.True(t, ok, "output = %v", out)
		return s
	}

	t.Run("one-start-per-run", func(t *testing.T) {
		t.Parallel()
		ampel, err := New()
		require.NoError(t, err)
		set := &papi.PolicySet{Id: "set", Policies: []*papi.Policy{startedPolicy("a"), startedPolicy("b")}}
		res, err := ampel.Verify(context.Background(), whenTestOptions(), set, whenTestSubject())
		require.NoError(t, err)
		rs, ok := res.(*papi.ResultSet)
		require.True(t, ok)
		require.Len(t, rs.GetResults(), 2)
		require.Equal(t, startedOutput(t, rs.GetResults()[0]), startedOutput(t, rs.GetResults()[1]), "both policies read the run's start")
	})

	t.Run("a-start-the-caller-sets", func(t *testing.T) {
		t.Parallel()
		ampel, err := New()
		require.NoError(t, err)
		opts := whenTestOptions()
		opts.RunStarted = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
		p := gatedPolicy("stamped", "ampel.started() == timestamp('2026-10-16T12:00:00Z')")
		res, err := ampel.VerifySubjectWithPolicy(context.Background(), opts, p, whenTestSubject())
		require.NoError(t, err)
		require.Equal(t, papi.StatusPASS, res.GetStatus(), "the condition read the start the caller set")
	})
}
