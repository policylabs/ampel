// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package gotable

import (
	"testing"

	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
)

// pass builds a passing policy result carrying one assessment per message.
func pass(msgs ...string) *papi.Result {
	res := &papi.Result{Status: papi.StatusPASS}
	for _, m := range msgs {
		res.EvalResults = append(res.EvalResults, &papi.EvalResult{
			Status:     papi.StatusPASS,
			Assessment: &papi.Assessment{Message: m},
		})
	}
	return res
}

// fail builds a failing policy result carrying one error per message.
func fail(msgs ...string) *papi.Result {
	res := &papi.Result{Status: papi.StatusFAIL}
	for _, m := range msgs {
		res.EvalResults = append(res.EvalResults, &papi.EvalResult{
			Status: papi.StatusFAIL,
			Error:  &papi.Error{Message: m},
		})
	}
	return res
}

func TestBlockAssessments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		assertMode string
		results    []*papi.Result
		expected   []string
	}{
		{
			name:     "single policy",
			results:  []*papi.Result{pass("SBOM is signed")},
			expected: []string{"SBOM is signed"},
		},
		{
			// Default (AND) mode: every policy had to pass, so report all.
			name:       "and mode reports every policy",
			assertMode: "",
			results:    []*papi.Result{pass("has author"), pass("has timestamp")},
			expected:   []string{"has author", "has timestamp"},
		},
		{
			name:       "explicit and mode reports every policy",
			assertMode: "AND",
			results:    []*papi.Result{pass("has author"), pass("has timestamp")},
			expected:   []string{"has author", "has timestamp"},
		},
		{
			// OR mode: only the policy that carried the block is reported.
			name:       "or mode reports only the deciding policy",
			assertMode: "OR",
			results:    []*papi.Result{fail("no purl"), pass("has CPE")},
			expected:   []string{"has CPE"},
		},
		{
			name:       "or mode stops at the first passing policy",
			assertMode: "OR",
			results:    []*papi.Result{pass("has purl"), pass("has CPE")},
			expected:   []string{"has purl"},
		},
		{
			// A silent deciding policy must not blank the cell when a later
			// passing policy has something to report.
			name:       "or mode skips a passing policy with no message",
			assertMode: "OR",
			results:    []*papi.Result{pass(), pass("has CPE")},
			expected:   []string{"has CPE"},
		},
		{
			name:       "failed policies are ignored",
			assertMode: "AND",
			results:    []*papi.Result{pass("has author"), fail("no license")},
			expected:   []string{"has author"},
		},
		{
			name:     "duplicate messages are collapsed",
			results:  []*papi.Result{pass("has author"), pass("has author")},
			expected: []string{"has author"},
		},
		{
			name:     "no assessment messages",
			results:  []*papi.Result{pass()},
			expected: []string{},
		},
		{
			name:     "no results",
			results:  []*papi.Result{},
			expected: []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			block := &papi.BlockEvalResult{
				Status:  papi.StatusPASS,
				Meta:    &papi.PolicyBlockMeta{AssertMode: tc.assertMode},
				Results: tc.results,
			}
			require.Equal(t, tc.expected, blockAssessments(block))
		})
	}
}

// A policy in OR assert mode passes with some of its tenets failing. Only
// the tenets that actually passed carry an assessment worth showing.
func TestBlockAssessmentsSkipsFailedTenets(t *testing.T) {
	t.Parallel()
	block := &papi.BlockEvalResult{
		Status: papi.StatusPASS,
		Meta:   &papi.PolicyBlockMeta{},
		Results: []*papi.Result{
			{
				Status: papi.StatusPASS,
				EvalResults: []*papi.EvalResult{
					{Status: papi.StatusFAIL, Error: &papi.Error{Message: "no purl"}},
					{Status: papi.StatusPASS, Assessment: &papi.Assessment{Message: "has CPE"}},
				},
			},
		},
	}
	require.Equal(t, []string{"has CPE"}, blockAssessments(block))
}
