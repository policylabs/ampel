// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"testing"
	"time"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/policylabs/ampel/pkg/evaluator/options"
)

// typedPredicate is a minimal attestation.Predicate implementation that
// returns a configurable predicate type. Used only in tests.
type typedPredicate struct {
	predType attestation.PredicateType
}

func (tp *typedPredicate) GetType() attestation.PredicateType        { return tp.predType }
func (tp *typedPredicate) SetType(attestation.PredicateType) error   { return nil }
func (tp *typedPredicate) GetParsed() any                            { return nil }
func (tp *typedPredicate) GetData() []byte                           { return []byte("{}") }
func (tp *typedPredicate) GetVerification() attestation.Verification { return nil }
func (tp *typedPredicate) GetOrigin() attestation.Subject            { return nil }
func (tp *typedPredicate) SetOrigin(attestation.Subject)             {}
func (tp *typedPredicate) SetVerification(attestation.Verification)  {}

func TestPolicySetExpiration(t *testing.T) {
	sub := &gointoto.ResourceDescriptor{}
	t.Parallel()
	for _, tt := range []struct {
		name      string
		mustPass  bool
		mustErr   bool
		opts      *VerificationOptions
		policySet *papi.PolicySet
	}{
		{
			"normal", true, false, &DefaultVerificationOptions,
			&papi.PolicySet{
				Meta: &papi.PolicySetMeta{
					Expiration: timestamppb.New(time.Now().Add(1 * time.Hour)),
				},
				Policies: []*papi.Policy{},
			},
		},
		{
			"expired", false, false, &DefaultVerificationOptions,
			&papi.PolicySet{
				Meta: &papi.PolicySetMeta{
					Expiration: timestamppb.New(time.Now().Add(-1 * time.Hour)),
				},
				Policies: []*papi.Policy{},
			},
		},
		{
			"valid-with-opts-disabled", true, false, &VerificationOptions{EnforceExpiration: false, EvaluatorOptions: options.Default},
			&papi.PolicySet{
				Meta: &papi.PolicySetMeta{
					Expiration: timestamppb.New(time.Now().Add(1 * time.Hour)),
				},
				Policies: []*papi.Policy{},
			},
		},
		{
			"expired-with-opts-disabled", true, false, &VerificationOptions{EnforceExpiration: false, EvaluatorOptions: options.Default},
			&papi.PolicySet{
				Meta: &papi.PolicySetMeta{
					Expiration: timestamppb.New(time.Now().Add(-1 * time.Hour)),
				},
				Policies: []*papi.Policy{},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ampel := &Ampel{
				impl: &defaultIplementation{},
			}
			res, err := ampel.Verify(t.Context(), tt.opts, tt.policySet, sub)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.mustPass, res.GetStatus() == papi.StatusPASS)
		})
	}
}

func TestPolicyPredicateMismatch(t *testing.T) {
	t.Parallel()

	typeX := attestation.PredicateType("https://example.com/type-x")
	typeY := attestation.PredicateType("https://example.com/type-y")
	typeZ := attestation.PredicateType("https://example.com/type-z")

	predX := &typedPredicate{predType: typeX}
	predY := &typedPredicate{predType: typeY}

	for _, tc := range []struct {
		name   string
		policy *papi.Policy
		preds  []attestation.Predicate
		want   bool
	}{
		{
			name: "no-declared-types-returns-false",
			policy: &papi.Policy{
				Id:     "unconstrained",
				Tenets: []*papi.Tenet{{Id: "t1", Code: "true"}},
			},
			preds: []attestation.Predicate{predX},
			want:  false,
		},
		{
			name: "declared-types-with-matching-predicate-returns-false",
			policy: &papi.Policy{
				Id: "matches",
				Tenets: []*papi.Tenet{{
					Id:   "t1",
					Code: "true",
					Predicates: &papi.PredicateSpec{
						Types: []string{string(typeX)},
					},
				}},
			},
			preds: []attestation.Predicate{predX},
			want:  false,
		},
		{
			name: "declared-types-with-no-matching-predicate-returns-true",
			policy: &papi.Policy{
				Id: "no-match",
				Tenets: []*papi.Tenet{{
					Id:   "t1",
					Code: "true",
					Predicates: &papi.PredicateSpec{
						Types: []string{string(typeZ)},
					},
				}},
			},
			preds: []attestation.Predicate{predX},
			want:  true,
		},
		{
			name: "policy-level-types-match",
			policy: &papi.Policy{
				Id: "policy-level",
				Predicates: &papi.PredicateSpec{
					Types: []string{string(typeX)},
				},
				Tenets: []*papi.Tenet{{Id: "t1", Code: "true"}},
			},
			preds: []attestation.Predicate{predX},
			want:  false,
		},
		{
			name: "policy-level-types-no-match",
			policy: &papi.Policy{
				Id: "policy-level-miss",
				Predicates: &papi.PredicateSpec{
					Types: []string{string(typeZ)},
				},
				Tenets: []*papi.Tenet{{Id: "t1", Code: "true"}},
			},
			preds: []attestation.Predicate{predX},
			want:  true,
		},
		{
			name: "mixed-tenets-some-match-returns-false",
			policy: &papi.Policy{
				Id: "mixed",
				Tenets: []*papi.Tenet{
					{
						Id:   "t1",
						Code: "true",
						Predicates: &papi.PredicateSpec{
							Types: []string{string(typeX)},
						},
					},
					{
						Id:   "t2",
						Code: "true",
						Predicates: &papi.PredicateSpec{
							Types: []string{string(typeZ)},
						},
					},
				},
			},
			preds: []attestation.Predicate{predX},
			want:  false,
		},
		{
			name: "multiple-predicates-one-matches",
			policy: &papi.Policy{
				Id: "multi-pred",
				Tenets: []*papi.Tenet{{
					Id:   "t1",
					Code: "true",
					Predicates: &papi.PredicateSpec{
						Types: []string{string(typeY)},
					},
				}},
			},
			preds: []attestation.Predicate{predX, predY},
			want:  false,
		},
		{
			name: "empty-preds-with-declared-types-returns-true",
			policy: &papi.Policy{
				Id: "empty-preds",
				Tenets: []*papi.Tenet{{
					Id:   "t1",
					Code: "true",
					Predicates: &papi.PredicateSpec{
						Types: []string{string(typeX)},
					},
				}},
			},
			preds: []attestation.Predicate{},
			want:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := policyPredicateMismatch(tc.policy, tc.preds)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSkipPolicyPredicateMismatch(t *testing.T) {
	t.Parallel()

	policy := &papi.Policy{
		Id: "test-policy",
		Meta: &papi.Meta{
			Version: 1,
		},
	}
	subject := &gointoto.ResourceDescriptor{
		Name:   "test-subject",
		Digest: map[string]string{"sha256": "abcd1234"},
	}

	result := skipPolicyPredicateMismatch(policy, subject)

	require.Equal(t, papi.StatusSKIP, result.GetStatus())
	require.Equal(t, "test-policy", result.GetPolicy().GetId())
	require.Equal(t, int64(1), result.GetPolicy().GetVersion())
	require.NotNil(t, result.GetMeta())
	require.NotNil(t, result.GetDateStart())
	require.NotNil(t, result.GetDateEnd())

	require.Len(t, result.GetEvalResults(), 1)
	er := result.GetEvalResults()[0]
	require.Equal(t, "predicate-match", er.GetId())
	require.Equal(t, papi.StatusSKIP, er.GetStatus())
	require.NotNil(t, er.GetAssessment())
	require.Contains(t, er.GetAssessment().GetMessage(), "no attestations match")
	require.Nil(t, er.GetError())
}

func TestSkipUnmatchedPredicatePolicy(t *testing.T) {
	t.Parallel()

	// Policy A has tenets with no predicate type constraints (unconstrained).
	// It always evaluates regardless of the attestation type.
	policyA := &papi.Policy{
		Id:   "unconstrained-policy",
		Meta: &papi.Meta{},
		Tenets: []*papi.Tenet{{
			Id:         "t1",
			Code:       "true",
			Assessment: &papi.Assessment{Message: "evaluated"},
		}},
	}

	// Policy B declares a specific predicate type that will not be present
	// in the available predicates (no attestations are provided). This
	// should trigger the predicate-type skip.
	policyB := &papi.Policy{
		Id:   "typed-policy",
		Meta: &papi.Meta{},
		Tenets: []*papi.Tenet{{
			Id:   "t1",
			Code: "true",
			Predicates: &papi.PredicateSpec{
				Types: []string{"https://example.com/branch-rules"},
			},
			Assessment: &papi.Assessment{Message: "should not run"},
		}},
	}

	set := &papi.PolicySet{
		Id:       "mixed-set",
		Policies: []*papi.Policy{policyA, policyB},
	}

	ampel, err := New()
	require.NoError(t, err)

	rs, err := ampel.VerifySubjectWithPolicySet(
		context.Background(), whenTestOptions(), set, whenTestSubject(),
	)
	require.NoError(t, err)

	// The set should PASS: unconstrained policy passes, typed policy is skipped.
	require.Equal(t, papi.StatusPASS, rs.GetStatus(),
		"SKIP does not count against the set; the passing policy determines the result")

	require.Len(t, rs.GetResults(), 2)

	// Policy A: unconstrained, should be evaluated and pass.
	resA := rs.GetResults()[0]
	require.Equal(t, papi.StatusPASS, resA.GetStatus())
	require.Equal(t, "unconstrained-policy", resA.GetPolicy().GetId())

	// Policy B: typed, should be skipped due to predicate type mismatch.
	resB := rs.GetResults()[1]
	require.Equal(t, papi.StatusSKIP, resB.GetStatus())
	require.Equal(t, "typed-policy", resB.GetPolicy().GetId())
	require.Len(t, resB.GetEvalResults(), 1)
	require.Equal(t, "predicate-match", resB.GetEvalResults()[0].GetId())
	require.Equal(t, papi.StatusSKIP, resB.GetEvalResults()[0].GetStatus())
	require.Contains(t, resB.GetEvalResults()[0].GetAssessment().GetMessage(), "no attestations match")
}

func TestEnforceOFFProducesSoftfail(t *testing.T) {
	t.Parallel()

	// A policy with enforce OFF and an unconstrained tenet that always fails.
	// Because predicate types are unconstrained the mismatch check does not
	// fire, the tenet evaluates and fails, and AssertResult downgrades the
	// FAIL to SOFTFAIL.
	policy := &papi.Policy{
		Id:   "enforce-off-fail",
		Meta: &papi.Meta{Enforce: "OFF"},
		Tenets: []*papi.Tenet{{
			Id:   "t1",
			Code: "false",
			Error: &papi.Error{
				Message: "expected failure",
			},
		}},
	}

	set := &papi.PolicySet{
		Id:       "softfail-set",
		Policies: []*papi.Policy{policy},
	}

	ampel, err := New()
	require.NoError(t, err)

	rs, err := ampel.VerifySubjectWithPolicySet(
		context.Background(), whenTestOptions(), set, whenTestSubject(),
	)
	require.NoError(t, err)
	require.Len(t, rs.GetResults(), 1)

	res := rs.GetResults()[0]
	require.Equal(t, papi.StatusSOFTFAIL, res.GetStatus(),
		"enforce OFF must downgrade FAIL to SOFTFAIL when tenet evaluation fails")
	require.Equal(t, "enforce-off-fail", res.GetPolicy().GetId())
}

func TestEnforceOFFMismatchedPredicatesProducesSkip(t *testing.T) {
	t.Parallel()

	// A policy with enforce OFF that declares a predicate type not present
	// in the available attestations. The predicate-type mismatch check fires
	// before AssertResult, producing SKIP instead of SOFTFAIL.
	policy := &papi.Policy{
		Id:   "enforce-off-mismatch",
		Meta: &papi.Meta{Enforce: "OFF"},
		Tenets: []*papi.Tenet{{
			Id:   "t1",
			Code: "false",
			Predicates: &papi.PredicateSpec{
				Types: []string{"https://example.com/nonexistent"},
			},
			Error: &papi.Error{
				Message: "should never run",
			},
		}},
	}

	set := &papi.PolicySet{
		Id:       "skip-not-softfail-set",
		Policies: []*papi.Policy{policy},
	}

	ampel, err := New()
	require.NoError(t, err)

	rs, err := ampel.VerifySubjectWithPolicySet(
		context.Background(), whenTestOptions(), set, whenTestSubject(),
	)
	require.NoError(t, err)
	require.Len(t, rs.GetResults(), 1)

	res := rs.GetResults()[0]
	require.Equal(t, papi.StatusSKIP, res.GetStatus(),
		"SKIP must take precedence over SOFTFAIL when predicate types do not match")
	require.Equal(t, "enforce-off-mismatch", res.GetPolicy().GetId())

	require.Len(t, res.GetEvalResults(), 1)
	require.Equal(t, "predicate-match", res.GetEvalResults()[0].GetId())
	require.Equal(t, papi.StatusSKIP, res.GetEvalResults()[0].GetStatus())
}

func TestMixedSetWithSkipAndSoftfail(t *testing.T) {
	t.Parallel()

	// Policy A: unconstrained, always passes.
	policyA := &papi.Policy{
		Id:   "pass-policy",
		Meta: &papi.Meta{},
		Tenets: []*papi.Tenet{{
			Id:         "t1",
			Code:       "true",
			Assessment: &papi.Assessment{Message: "all good"},
		}},
	}

	// Policy B: enforce OFF, declares an unmatched predicate type -> SKIP.
	policyB := &papi.Policy{
		Id:   "skip-policy",
		Meta: &papi.Meta{Enforce: "OFF"},
		Tenets: []*papi.Tenet{{
			Id:   "t1",
			Code: "false",
			Predicates: &papi.PredicateSpec{
				Types: []string{"https://example.com/missing-type"},
			},
		}},
	}

	// Policy C: enforce OFF, unconstrained, tenet fails -> SOFTFAIL.
	policyC := &papi.Policy{
		Id:   "softfail-policy",
		Meta: &papi.Meta{Enforce: "OFF"},
		Tenets: []*papi.Tenet{{
			Id:   "t1",
			Code: "false",
			Error: &papi.Error{
				Message: "soft failure",
			},
		}},
	}

	set := &papi.PolicySet{
		Id:       "mixed-set",
		Policies: []*papi.Policy{policyA, policyB, policyC},
	}

	ampel, err := New()
	require.NoError(t, err)

	rs, err := ampel.VerifySubjectWithPolicySet(
		context.Background(), whenTestOptions(), set, whenTestSubject(),
	)
	require.NoError(t, err)

	// The set should PASS: SKIP and SOFTFAIL are non-blocking.
	require.Equal(t, papi.StatusPASS, rs.GetStatus(),
		"SKIP and SOFTFAIL must not block the policy set from passing")

	require.Len(t, rs.GetResults(), 3)

	resA := rs.GetResults()[0]
	require.Equal(t, papi.StatusPASS, resA.GetStatus())
	require.Equal(t, "pass-policy", resA.GetPolicy().GetId())

	resB := rs.GetResults()[1]
	require.Equal(t, papi.StatusSKIP, resB.GetStatus())
	require.Equal(t, "skip-policy", resB.GetPolicy().GetId())

	resC := rs.GetResults()[2]
	require.Equal(t, papi.StatusSOFTFAIL, resC.GetStatus())
	require.Equal(t, "softfail-policy", resC.GetPolicy().GetId())
}
