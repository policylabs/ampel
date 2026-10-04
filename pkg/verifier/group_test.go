// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"testing"

	gointoto "github.com/in-toto/attestation/go/v1"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

func TestPolicyGroupEnforceOFF(t *testing.T) {
	t.Parallel()

	passingPolicy := &papi.Policy{
		Id:   "pass",
		Meta: &papi.Meta{AssertMode: "OR"},
		Tenets: []*papi.Tenet{
			{Id: "t1", Code: "true"},
		},
	}

	failingPolicy := &papi.Policy{
		Id:   "fail",
		Meta: &papi.Meta{AssertMode: "OR"},
		Tenets: []*papi.Tenet{
			{Id: "t1", Code: "false", Error: &papi.Error{Message: "expected failure"}},
		},
	}

	subject := &gointoto.ResourceDescriptor{
		Name:   "test-subject",
		Digest: map[string]string{"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
	}

	for _, tc := range []struct {
		name           string
		group          *papi.PolicyGroup
		expectedStatus string
	}{
		{
			name: "enforce-OFF-failing-group-softfails",
			group: &papi.PolicyGroup{
				Id:   "group-enforce-off-fail",
				Meta: &papi.PolicyGroupMeta{Enforce: "OFF"},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
				},
			},
			expectedStatus: papi.StatusSOFTFAIL,
		},
		{
			name: "enforce-OFF-passing-group-still-passes",
			group: &papi.PolicyGroup{
				Id:   "group-enforce-off-pass",
				Meta: &papi.PolicyGroupMeta{Enforce: "OFF"},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
				},
			},
			expectedStatus: papi.StatusPASS,
		},
		{
			name: "enforce-ON-failing-group-hard-fails",
			group: &papi.PolicyGroup{
				Id:   "group-enforce-on-fail",
				Meta: &papi.PolicyGroupMeta{},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
				},
			},
			expectedStatus: papi.StatusFAIL,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := &VerificationOptions{
				EvaluatorOptions:    options.Default,
				DefaultEvaluator:    DefaultVerificationOptions.DefaultEvaluator,
				EnforceExpiration:   false,
				AllowEmptySetChains: true,
			}

			ampel, err := New()
			require.NoError(t, err)

			res, err := ampel.VerifySubjectWithPolicyGroup(context.Background(), opts, tc.group, subject)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, tc.expectedStatus, res.GetStatus())
		})
	}
}

func TestPolicyGroupAssertMode(t *testing.T) {
	t.Parallel()

	passingPolicy := &papi.Policy{
		Id:   "pass",
		Meta: &papi.Meta{AssertMode: "OR"},
		Tenets: []*papi.Tenet{
			{Id: "t1", Code: "true"},
		},
	}

	failingPolicy := &papi.Policy{
		Id:   "fail",
		Meta: &papi.Meta{AssertMode: "OR"},
		Tenets: []*papi.Tenet{
			{Id: "t1", Code: "false", Error: &papi.Error{Message: "expected failure"}},
		},
	}

	subject := &gointoto.ResourceDescriptor{
		Name:   "test-subject",
		Digest: map[string]string{"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
	}

	for _, tc := range []struct {
		name     string
		group    *papi.PolicyGroup
		mustPass bool
	}{
		{
			name: "AND-default-all-pass",
			group: &papi.PolicyGroup{
				Id:   "group-and-default",
				Meta: &papi.PolicyGroupMeta{},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
				},
			},
			mustPass: true,
		},
		{
			name: "AND-default-one-fails",
			group: &papi.PolicyGroup{
				Id:   "group-and-default-fail",
				Meta: &papi.PolicyGroupMeta{},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
				},
			},
			mustPass: false,
		},
		{
			name: "AND-explicit-all-pass",
			group: &papi.PolicyGroup{
				Id:   "group-and-explicit",
				Meta: &papi.PolicyGroupMeta{AssertMode: "AND"},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
				},
			},
			mustPass: true,
		},
		{
			name: "AND-explicit-one-fails",
			group: &papi.PolicyGroup{
				Id:   "group-and-explicit-fail",
				Meta: &papi.PolicyGroupMeta{AssertMode: "AND"},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
				},
			},
			mustPass: false,
		},
		{
			name: "OR-one-passes",
			group: &papi.PolicyGroup{
				Id:   "group-or-one-pass",
				Meta: &papi.PolicyGroupMeta{AssertMode: "OR"},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
				},
			},
			mustPass: true,
		},
		{
			name: "OR-all-pass",
			group: &papi.PolicyGroup{
				Id:   "group-or-all-pass",
				Meta: &papi.PolicyGroupMeta{AssertMode: "OR"},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
				},
			},
			mustPass: true,
		},
		{
			name: "OR-all-fail",
			group: &papi.PolicyGroup{
				Id:   "group-or-all-fail",
				Meta: &papi.PolicyGroupMeta{AssertMode: "OR"},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
				},
			},
			mustPass: false,
		},
		{
			name: "OR-first-fails-second-passes",
			group: &papi.PolicyGroup{
				Id:   "group-or-reverse",
				Meta: &papi.PolicyGroupMeta{AssertMode: "OR"},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
				},
			},
			mustPass: true,
		},
		{
			name: "AND-all-fail",
			group: &papi.PolicyGroup{
				Id:   "group-and-all-fail",
				Meta: &papi.PolicyGroupMeta{},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
				},
			},
			mustPass: false,
		},
		{
			name: "OR-three-blocks-middle-passes",
			group: &papi.PolicyGroup{
				Id:   "group-or-three",
				Meta: &papi.PolicyGroupMeta{AssertMode: "OR"},
				Blocks: []*papi.PolicyBlock{
					{Id: "block-1", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
					{Id: "block-2", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{passingPolicy}},
					{Id: "block-3", Meta: &papi.PolicyBlockMeta{}, Policies: []*papi.Policy{failingPolicy}},
				},
			},
			mustPass: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := &VerificationOptions{
				EvaluatorOptions:    options.Default,
				DefaultEvaluator:    DefaultVerificationOptions.DefaultEvaluator,
				EnforceExpiration:   false,
				AllowEmptySetChains: true,
			}

			ampel, err := New()
			require.NoError(t, err)

			res, err := ampel.VerifySubjectWithPolicyGroup(context.Background(), opts, tc.group, subject)
			require.NoError(t, err)
			require.NotNil(t, res)

			if tc.mustPass {
				require.Equal(t, papi.StatusPASS, res.GetStatus(), "group should PASS")
			} else {
				require.Equal(t, papi.StatusFAIL, res.GetStatus(), "group should FAIL")
			}
		})
	}
}
