// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package summary

import (
	"bytes"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/stretchr/testify/require"
)

func testPolicies(t *testing.T) (pass, fail, soft *papi.Result) {
	t.Helper()
	passTenet := &papi.EvalResult{
		Status:     papi.StatusPASS,
		Statements: []*papi.StatementRef{{}},
		Assessment: &papi.Assessment{Message: "build point found"},
	}
	// A tenet that never evaluated for lack of attestations
	starvedTenet := &papi.EvalResult{
		Status: papi.StatusFAIL,
		Error:  &papi.Error{Message: "required attestations missing"},
	}
	failTenet := &papi.EvalResult{
		Status:     papi.StatusFAIL,
		Statements: []*papi.StatementRef{{}},
		Error:      &papi.Error{Message: "build point mismatch"},
	}

	pass = &papi.Result{
		Status: papi.StatusPASS, Policy: &papi.PolicyRef{Id: "pol-pass"},
		EvalResults: []*papi.EvalResult{starvedTenet, passTenet},
	}
	fail = &papi.Result{
		Status: papi.StatusFAIL, Policy: &papi.PolicyRef{Id: "pol-fail"},
		EvalResults: []*papi.EvalResult{starvedTenet, failTenet},
	}
	soft = &papi.Result{
		Status: papi.StatusSOFTFAIL, Policy: &papi.PolicyRef{Id: "pol-soft"},
		EvalResults: []*papi.EvalResult{failTenet},
	}
	return pass, fail, soft
}

func TestRenderResultSet(t *testing.T) {
	t.Parallel()
	pass, fail, soft := testPolicies(t)
	setRef := &papi.PolicyRef{Id: "test-set"}

	for _, tc := range []struct {
		name   string
		rset   *papi.ResultSet
		expect string
	}{
		// Single-policy sets render as the policy line, no set prefix.
		// The passing policy picks the evaluated tenet's assessment over
		// the starved tenet's error.
		{
			"single-pass",
			&papi.ResultSet{Status: papi.StatusPASS, Results: []*papi.Result{pass}},
			"🟢 pol-pass: build point found\n",
		},
		// The failing policy picks the evaluated failing tenet's error
		{
			"single-fail",
			&papi.ResultSet{Status: papi.StatusFAIL, Results: []*papi.Result{fail}},
			"🔴 pol-fail: build point mismatch\n",
		},
		{
			"set-pass",
			&papi.ResultSet{Status: papi.StatusPASS, PolicySet: setRef, Results: []*papi.Result{pass, pass}},
			"🟢 test-set: all 2 policies passed\n",
		},
		{
			"set-fail",
			&papi.ResultSet{Status: papi.StatusFAIL, PolicySet: setRef, Results: []*papi.Result{pass, fail, pass}},
			"🔴 test-set: pol-fail: build point mismatch (1 of 3 policies failed)\n",
		},
		{
			"set-softfail",
			&papi.ResultSet{Status: papi.StatusSOFTFAIL, PolicySet: setRef, Results: []*papi.Result{pass, soft}},
			"🟡 test-set: pol-soft: build point mismatch (1 of 2 policies softfailed)\n",
		},
		// Hard failures win over softfails in the headline
		{
			"set-fail-and-softfail",
			&papi.ResultSet{Status: papi.StatusFAIL, PolicySet: setRef, Results: []*papi.Result{soft, fail}},
			"🔴 test-set: pol-fail: build point mismatch (1 of 2 policies failed)\n",
		},
		{
			"empty-set",
			&papi.ResultSet{Status: papi.StatusPASS, PolicySet: setRef},
			"🟢 test-set: no policy results found\n",
		},
		{
			"empty-set-with-error",
			&papi.ResultSet{Status: papi.StatusFAIL, Error: &papi.Error{Message: "evaluation blew up"}},
			"🔴 evaluation blew up\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var b bytes.Buffer
			require.NoError(t, New().RenderResultSet(&b, tc.rset))
			require.Equal(t, tc.expect, b.String())
		})
	}
}

func TestRenderResultGroup(t *testing.T) {
	t.Parallel()
	_, fail, _ := testPolicies(t)

	group := &papi.ResultGroup{
		Status: papi.StatusFAIL,
		Group:  &papi.PolicyGroupRef{Id: "test-group"},
		EvalResults: []*papi.BlockEvalResult{
			{Status: papi.StatusPASS},
			{Status: papi.StatusFAIL, Results: []*papi.Result{fail}},
		},
	}
	var b bytes.Buffer
	require.NoError(t, New().RenderResultGroup(&b, group))
	require.Equal(t, "🔴 test-group: build point mismatch\n", b.String())
}
