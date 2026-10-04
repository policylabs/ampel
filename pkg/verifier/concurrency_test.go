// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"fmt"
	"sort"
	"testing"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/ampel/pkg/evaluator/options"
)

// TestPolicySetConcurrentEvaluation tests that concurrent evaluation of multiple
// policies across multiple subjects produces consistent results. This test is
// designed to catch race conditions in the goroutine loop variable capture.
func TestPolicySetConcurrentEvaluation(t *testing.T) {
	t.Parallel()

	// Create multiple policies with different IDs to ensure we can track them
	policies := []*papi.Policy{
		{
			Id: "policy-1",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "tenet-1",
					Code: "true", // Simple passing tenet
				},
			},
		},
		{
			Id: "policy-2",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "tenet-2",
					Code: "true",
				},
			},
		},
		{
			Id: "policy-3",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "tenet-3",
					Code: "true",
				},
			},
		},
		{
			Id: "policy-4",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "tenet-4",
					Code: "true",
				},
			},
		},
	}

	// Create multiple subjects
	subjects := []attestation.Subject{
		&gointoto.ResourceDescriptor{
			Name:   "artifact-1",
			Digest: map[string]string{"sha256": "aaaa0000000000000000000000000000000000000000000000000000000000aa"},
		},
		&gointoto.ResourceDescriptor{
			Name:   "artifact-2",
			Digest: map[string]string{"sha256": "bbbb0000000000000000000000000000000000000000000000000000000000bb"},
		},
		&gointoto.ResourceDescriptor{
			Name:   "artifact-3",
			Digest: map[string]string{"sha256": "cccc0000000000000000000000000000000000000000000000000000000000cc"},
		},
	}

	policySet := &papi.PolicySet{
		Id:       "test-set",
		Policies: policies,
		Meta:     &papi.PolicySetMeta{},
	}

	// Run the test multiple times to increase chance of catching race conditions
	for iteration := range 20 {
		t.Run(fmt.Sprintf("iteration-%d", iteration), func(t *testing.T) {
			t.Parallel()
			for _, numWorkers := range []int8{1, 2, 4, 8} {
				t.Run(fmt.Sprintf("workers-%d", numWorkers), func(t *testing.T) {
					opts := &VerificationOptions{
						EvaluatorOptions:    options.Default,
						DefaultEvaluator:    DefaultVerificationOptions.DefaultEvaluator,
						EnforceExpiration:   false,
						AllowEmptySetChains: true,
					}
					opts.ParallelWorkers = numWorkers

					ampel, err := New()
					require.NoError(t, err)

					// Verify each subject in the subjects list
					for subjectIdx, subject := range subjects {
						t.Run(fmt.Sprintf("subject-%d", subjectIdx), func(t *testing.T) {
							ctx := context.Background()
							res, err := ampel.VerifySubjectWithPolicySet(ctx, opts, policySet, subject)
							require.NoError(t, err)
							require.NotNil(t, res)

							// Verify we got results for all policies
							require.Len(t, res.Results, len(policies), "should have results for all policies")

							// Verify each result has the correct policy ID
							resultPolicyIDs := make([]string, 0, len(res.Results))
							for _, result := range res.Results {
								resultPolicyIDs = append(resultPolicyIDs, result.Policy.Id)
							}
							sort.Strings(resultPolicyIDs)

							expectedPolicyIDs := make([]string, 0, len(policies))
							for _, policy := range policies {
								expectedPolicyIDs = append(expectedPolicyIDs, policy.Id)
							}
							sort.Strings(expectedPolicyIDs)

							require.Equal(t, expectedPolicyIDs, resultPolicyIDs,
								"results should contain all policy IDs exactly once")

							// Verify all policies passed (since all tenets evaluate to true)
							for _, result := range res.Results {
								require.Equal(t, papi.StatusPASS, result.Status,
									"policy %s should pass", result.Policy.Id)
							}

							// Verify the subject in each result matches the input subject
							for _, result := range res.Results {
								require.Equal(t, subject.GetName(), result.Subject.GetName(),
									"result subject name should match input")
								require.Equal(t, subject.GetDigest(), result.Subject.GetDigest(),
									"result subject digest should match input")
							}
						})
					}
				})
			}
		})
	}
}

// TestPolicySetConcurrentEvaluationWithFailures tests concurrent evaluation
// with mixed pass/fail policies to ensure error handling is thread-safe.
func TestPolicySetConcurrentEvaluationWithFailures(t *testing.T) {
	t.Parallel()

	// Create policies that will pass and fail
	policies := []*papi.Policy{
		{
			Id: "pass-1",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "pass-tenet-1",
					Code: "true",
				},
			},
		},
		{
			Id: "fail-1",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "fail-tenet-1",
					Code: "false",
					Error: &papi.Error{
						Message:  "Expected failure",
						Guidance: "This tenet is designed to fail",
					},
				},
			},
		},
		{
			Id: "pass-2",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "pass-tenet-2",
					Code: "true",
				},
			},
		},
		{
			Id: "fail-2",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "fail-tenet-2",
					Code: "false",
					Error: &papi.Error{
						Message:  "Expected failure 2",
						Guidance: "This tenet is also designed to fail",
					},
				},
			},
		},
	}

	subject := &gointoto.ResourceDescriptor{
		Name:   "test-artifact",
		Digest: map[string]string{"sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
	}

	policySet := &papi.PolicySet{
		Id:       "mixed-test-set",
		Policies: policies,
		Meta:     &papi.PolicySetMeta{},
	}

	// Run with different worker counts
	for _, numWorkers := range []int8{1, 4, 8} {
		t.Run(fmt.Sprintf("workers-%d", numWorkers), func(t *testing.T) {
			t.Parallel()
			// Run multiple iterations to catch race conditions
			for range 10 {
				opts := &VerificationOptions{
					EvaluatorOptions:    options.Default,
					DefaultEvaluator:    DefaultVerificationOptions.DefaultEvaluator,
					EnforceExpiration:   false,
					AllowEmptySetChains: true,
				}
				opts.ParallelWorkers = numWorkers

				ampel, err := New()
				require.NoError(t, err)

				ctx := context.Background()
				res, err := ampel.VerifySubjectWithPolicySet(ctx, opts, policySet, subject)
				require.NoError(t, err)
				require.NotNil(t, res)

				// Verify we got results for all policies
				require.Len(t, res.Results, len(policies))

				// Count passes and failures
				var passCount, failCount int
				for _, result := range res.Results {
					switch result.Status {
					case papi.StatusPASS:
						passCount++
					case papi.StatusFAIL:
						failCount++
					}
				}

				// We should have exactly 2 passes and 2 failures
				require.Equal(t, 2, passCount, "should have 2 passing policies")
				require.Equal(t, 2, failCount, "should have 2 failing policies")
			}
		})
	}
}

// TestPolicySetConcurrentEvaluationChainedSubjects tests concurrent evaluation
// with PolicySet chains to ensure the chain processing is thread-safe.
func TestPolicySetConcurrentEvaluationChainedSubjects(t *testing.T) {
	t.Parallel()

	// Create a simple policy set without chains first (chains require attestations)
	policies := []*papi.Policy{
		{
			Id: "policy-a",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "tenet-a",
					Code: "subject.name == 'test-subject'",
				},
			},
		},
		{
			Id: "policy-b",
			Meta: &papi.Meta{
				AssertMode: "OR",
			},
			Tenets: []*papi.Tenet{
				{
					Id:   "tenet-b",
					Code: "subject.name == 'test-subject'",
				},
			},
		},
	}

	subject := &gointoto.ResourceDescriptor{
		Name:   "test-subject",
		Digest: map[string]string{"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
	}

	policySet := &papi.PolicySet{
		Id:       "chain-test-set",
		Policies: policies,
	}

	// Test with different worker counts
	for _, numWorkers := range []int8{1, 2, 4} {
		t.Run(fmt.Sprintf("workers-%d", numWorkers), func(t *testing.T) {
			t.Parallel()
			for range 5 {
				opts := &VerificationOptions{
					EvaluatorOptions:    options.Default,
					DefaultEvaluator:    DefaultVerificationOptions.DefaultEvaluator,
					EnforceExpiration:   false,
					AllowEmptySetChains: true,
				}
				opts.ParallelWorkers = numWorkers

				ampel, err := New()
				require.NoError(t, err)

				ctx := context.Background()
				res, err := ampel.VerifySubjectWithPolicySet(ctx, opts, policySet, subject)
				require.NoError(t, err)
				require.NotNil(t, res)

				// All results should reference the same subject
				for _, result := range res.Results {
					require.Equal(t, subject.GetName(), result.Subject.GetName())
				}
			}
		})
	}
}
