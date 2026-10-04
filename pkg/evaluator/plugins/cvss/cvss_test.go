// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cvss

import (
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func run(t *testing.T, expr string) any {
	t.Helper()
	p := New()
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)

	ast, iss := env.Compile(expr)
	require.NoError(t, iss.Err(), "compile %q", expr)

	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	require.NoError(t, err)

	result, _, err := program.Eval(p.VarValues(nil, nil, nil))
	require.NoError(t, err, "eval %q", expr)
	return result.Value()
}

const (
	v20       = `"AV:N/AC:L/Au:N/C:C/I:C/A:C"`
	v30       = `"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`
	v31       = `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`
	v31medium = `"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"`
	v31none   = `"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"`
	v40       = `"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"`
)

func TestScore(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		expr string
		want float64
	}{
		{"v2.0-high", `cvss.score(` + v20 + `)`, 10.0},
		{"v3.0-critical", `cvss.score(` + v30 + `)`, 9.8},
		{"v3.1-critical", `cvss.score(` + v31 + `)`, 9.8},
		{"v4.0-critical", `cvss.score(` + v40 + `)`, 9.3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := run(t, tc.expr).(float64)
			require.True(t, ok, "score should be float64, got %T", run(t, tc.expr))
			require.InDelta(t, tc.want, got, 0.05)
		})
	}
}

func TestSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		expr string
		want string
	}{
		{"v2.0-high", `cvss.severity(` + v20 + `)`, "HIGH"},
		{"v3.0-critical", `cvss.severity(` + v30 + `)`, "CRITICAL"},
		{"v3.1-critical", `cvss.severity(` + v31 + `)`, "CRITICAL"},
		{"v3.1-medium", `cvss.severity(` + v31medium + `)`, "MEDIUM"},
		{"v3.1-none", `cvss.severity(` + v31none + `)`, "NONE"},
		{"v4.0-critical", `cvss.severity(` + v40 + `)`, "CRITICAL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, tc.expr))
		})
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	require.Equal(t, "2.0", run(t, `cvss.version(`+v20+`)`))
	require.Equal(t, "3.0", run(t, `cvss.version(`+v30+`)`))
	require.Equal(t, "3.1", run(t, `cvss.version(`+v31+`)`))
	require.Equal(t, "4.0", run(t, `cvss.version(`+v40+`)`))
}

func TestIsValid(t *testing.T) {
	t.Parallel()
	require.Equal(t, true, run(t, `cvss.isValid(`+v20+`)`))
	require.Equal(t, true, run(t, `cvss.isValid(`+v30+`)`))
	require.Equal(t, true, run(t, `cvss.isValid(`+v31+`)`))
	require.Equal(t, true, run(t, `cvss.isValid(`+v40+`)`))
	require.Equal(t, false, run(t, `cvss.isValid("not-a-cvss-vector")`))
	require.Equal(t, false, run(t, `cvss.isValid("CVSS:3.1/AV:INVALID")`))
}

func TestGetStrict(t *testing.T) {
	t.Parallel()
	require.Equal(t, "N", run(t, `cvss.get(`+v20+`, "AV")`))
	require.Equal(t, "C", run(t, `cvss.get(`+v20+`, "C")`))
	require.Equal(t, "N", run(t, `cvss.get(`+v30+`, "AV")`))
	require.Equal(t, "H", run(t, `cvss.get(`+v30+`, "C")`))
	require.Equal(t, "N", run(t, `cvss.get(`+v31+`, "AV")`))
	require.Equal(t, "H", run(t, `cvss.get(`+v31+`, "C")`))
	require.Equal(t, "N", run(t, `cvss.get(`+v40+`, "AV")`))
	require.Equal(t, "H", run(t, `cvss.get(`+v40+`, "VC")`))
}

func TestGetStrictErrorOnUnknownMetric(t *testing.T) {
	t.Parallel()
	p := New()
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)

	// SC is a v4.0 metric; asking for it on a v3.1 vector should error.
	ast, iss := env.Compile(`cvss.get(` + v31 + `, "SC")`)
	require.NoError(t, iss.Err())
	program, err := env.Program(ast)
	require.NoError(t, err)
	_, _, err = program.Eval(p.VarValues(nil, nil, nil))
	require.Error(t, err)
}

func TestNamedAccessorsV20(t *testing.T) {
	t.Parallel()
	cases := []struct {
		fn   string
		want string
	}{
		{"attackVector", "N"},
		{"attackComplexity", "L"},
		{"authentication", "N"},
		{"confidentiality", "C"},
		{"integrity", "C"},
		{"availability", "C"},
	}
	for _, tc := range cases {
		t.Run(tc.fn, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, `cvss.`+tc.fn+`(`+v20+`)`))
		})
	}
}

func TestNamedAccessorsV30(t *testing.T) {
	t.Parallel()
	cases := []struct {
		fn   string
		want string
	}{
		{"attackVector", "N"},
		{"attackComplexity", "L"},
		{"privilegesRequired", "N"},
		{"userInteraction", "N"},
		{"scope", "U"},
		{"confidentiality", "H"},
		{"integrity", "H"},
		{"availability", "H"},
	}
	for _, tc := range cases {
		t.Run(tc.fn, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, `cvss.`+tc.fn+`(`+v30+`)`))
		})
	}
}

func TestNamedAccessorsV31(t *testing.T) {
	t.Parallel()
	cases := []struct {
		fn   string
		want string
	}{
		{"attackVector", "N"},
		{"attackComplexity", "L"},
		{"privilegesRequired", "N"},
		{"userInteraction", "N"},
		{"scope", "U"},
		{"confidentiality", "H"},
		{"integrity", "H"},
		{"availability", "H"},
	}
	for _, tc := range cases {
		t.Run(tc.fn, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, `cvss.`+tc.fn+`(`+v31+`)`))
		})
	}
}

func TestNamedAccessorsV40(t *testing.T) {
	t.Parallel()
	cases := []struct {
		fn   string
		want string
	}{
		{"attackVector", "N"},
		{"attackComplexity", "L"},
		{"attackRequirements", "N"},
		{"privilegesRequired", "N"},
		{"userInteraction", "N"},
		{"vulnConfidentiality", "H"},
		{"vulnIntegrity", "H"},
		{"vulnAvailability", "H"},
		{"subConfidentiality", "N"},
		{"subIntegrity", "N"},
		{"subAvailability", "N"},
	}
	for _, tc := range cases {
		t.Run(tc.fn, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, `cvss.`+tc.fn+`(`+v40+`)`))
		})
	}
}

func TestNamedAccessorReturnsEmptyForInapplicableVersion(t *testing.T) {
	t.Parallel()
	// v3.x/v4.0-only metrics on a v2.0 vector
	require.Empty(t, run(t, `cvss.privilegesRequired(`+v20+`)`))
	require.Empty(t, run(t, `cvss.userInteraction(`+v20+`)`))
	require.Empty(t, run(t, `cvss.scope(`+v20+`)`))
	require.Empty(t, run(t, `cvss.vulnConfidentiality(`+v20+`)`))
	require.Empty(t, run(t, `cvss.attackRequirements(`+v20+`)`))
	// v2.0-only metrics on a v3.0 vector
	require.Empty(t, run(t, `cvss.authentication(`+v30+`)`))
	require.Empty(t, run(t, `cvss.collateralDamagePotential(`+v30+`)`))
	// v4.0-only metrics on a v3.0 vector
	require.Empty(t, run(t, `cvss.vulnConfidentiality(`+v30+`)`))
	require.Empty(t, run(t, `cvss.attackRequirements(`+v30+`)`))
	// v2.0-only metrics on a v3.1 vector
	require.Empty(t, run(t, `cvss.authentication(`+v31+`)`))
	require.Empty(t, run(t, `cvss.collateralDamagePotential(`+v31+`)`))
	// v4.0-only metrics on a v3.1 vector
	require.Empty(t, run(t, `cvss.vulnConfidentiality(`+v31+`)`))
	require.Empty(t, run(t, `cvss.attackRequirements(`+v31+`)`))
	// v2.0-only metrics on a v4.0 vector
	require.Empty(t, run(t, `cvss.authentication(`+v40+`)`))
	require.Empty(t, run(t, `cvss.collateralDamagePotential(`+v40+`)`))
	// v3.x-only metrics on a v4.0 vector
	require.Empty(t, run(t, `cvss.modifiedConfidentiality(`+v40+`)`))
	// C/I/A do not exist in v4.0 (replaced by VC/VI/VA and SC/SI/SA)
	require.Empty(t, run(t, `cvss.confidentiality(`+v40+`)`))
	require.Empty(t, run(t, `cvss.integrity(`+v40+`)`))
	require.Empty(t, run(t, `cvss.availability(`+v40+`)`))
}

// TestVersionIsolation verifies that abbreviation clashes between versions are
// prevented: the same abbreviation can carry different semantics in different
// CVSS versions (e.g. "S" = Scope in v3.x vs Safety in v4.0).
func TestVersionIsolation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		expr string
	}{
		// "S" clash: safety must not return v2.0/v3.x Scope, scope must not return v4.0 Safety
		{"safety-on-v20", `cvss.safety(` + v20 + `)`},
		{"safety-on-v30", `cvss.safety(` + v30 + `)`},
		{"safety-on-v31", `cvss.safety(` + v31 + `)`},
		{"scope-on-v40", `cvss.scope(` + v40 + `)`},
		// "E" aliases must not cross versions
		{"exploitMaturity-on-v20", `cvss.exploitMaturity(` + v20 + `)`},
		{"exploitability-on-v30", `cvss.exploitability(` + v30 + `)`},
		{"exploitability-on-v31", `cvss.exploitability(` + v31 + `)`},
		{"exploitability-on-v40", `cvss.exploitability(` + v40 + `)`},
		// RL and RC are v2.0/v3.x temporal metrics absent from v4.0
		{"remediationLevel-on-v40", `cvss.remediationLevel(` + v40 + `)`},
		{"reportConfidence-on-v40", `cvss.reportConfidence(` + v40 + `)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Empty(t, run(t, tc.expr), "expected empty string for cross-version accessor")
		})
	}
}

// TestVersionIsolationPositive confirms the version-restricted accessors still
// return values when called against their correct version.
func TestVersionIsolationPositive(t *testing.T) {
	t.Parallel()
	require.Equal(t, "U", run(t, `cvss.scope(`+v30+`)`))
	require.Equal(t, "U", run(t, `cvss.scope(`+v31+`)`))
	require.Equal(t, "X", run(t, `cvss.safety(`+v40+`)`))
	require.Equal(t, "ND", run(t, `cvss.exploitability(`+v20+`)`))
	require.Equal(t, "X", run(t, `cvss.exploitMaturity(`+v30+`)`))
	require.Equal(t, "X", run(t, `cvss.exploitMaturity(`+v31+`)`))
	require.Equal(t, "X", run(t, `cvss.exploitMaturity(`+v40+`)`))
}

func TestParse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		expr      string
		wantKeys  map[string]any // spot-check a subset of keys
		wantScore float64
	}{
		{
			"v2.0", `cvss.parse(` + v20 + `)`,
			map[string]any{"version": "2.0", "severity": "HIGH", "AV": "N", "Au": "N", "C": "C"},
			10.0,
		},
		{
			"v3.0", `cvss.parse(` + v30 + `)`,
			map[string]any{"version": "3.0", "severity": "CRITICAL", "AV": "N", "C": "H"},
			9.8,
		},
		{
			"v3.1", `cvss.parse(` + v31 + `)`,
			map[string]any{"version": "3.1", "severity": "CRITICAL", "AV": "N", "C": "H"},
			9.8,
		},
		{
			"v4.0", `cvss.parse(` + v40 + `)`,
			map[string]any{"version": "4.0", "severity": "CRITICAL", "AV": "N", "VC": "H", "SC": "N"},
			9.3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := run(t, tc.expr)
			m, ok := got.(map[string]any)
			require.True(t, ok, "parse should return a map, got %T", got)

			score, ok := m["score"].(float64)
			require.True(t, ok, "score should be float64, got %T", m["score"])
			require.InDelta(t, tc.wantScore, score, 0.05)

			for k, v := range tc.wantKeys {
				require.Equal(t, v, m[k], "key %q", k)
			}
		})
	}
}

func TestInvalidVectorErrors(t *testing.T) {
	t.Parallel()
	p := New()
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)

	for _, expr := range []string{
		`cvss.score("not-a-vector")`,
		`cvss.severity("CVSS:3.1/AV:BOGUS")`,
		`cvss.get("not-a-vector", "AV")`,
	} {
		ast, iss := env.Compile(expr)
		require.NoError(t, iss.Err(), "compile %q", expr)
		program, err := env.Program(ast)
		require.NoError(t, err)
		_, _, err = program.Eval(p.VarValues(nil, nil, nil))
		require.Error(t, err, "expected error for %q", expr)
	}
}

func TestPolicyExpressions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		expr string
		want bool
	}{
		{
			"block critical",
			`cvss.score(` + v31 + `) >= 9.0`,
			true,
		},
		{
			"network-reachable check",
			`cvss.attackVector(` + v31 + `) == "N"`,
			true,
		},
		{
			"no-privileges-required",
			`cvss.privilegesRequired(` + v31 + `) == "N"`,
			true,
		},
		{
			"severity in set",
			`cvss.severity(` + v31 + `) in ["CRITICAL", "HIGH"]`,
			true,
		},
		{
			"combined v4.0 policy",
			`cvss.score(` + v40 + `) >= 9.0 && cvss.attackVector(` + v40 + `) == "N"`,
			true,
		},
		{
			"version guard",
			`cvss.version(` + v40 + `) == "4.0"`,
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, tc.expr))
		})
	}
}
