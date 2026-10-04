// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package semver

import (
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"
)

// run compiles and evaluates expr against a CEL env preloaded with
// the semver plugin. Returns the Go value produced by the expression.
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

func TestAccessorsReturnComponents(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		expr string
		want any
	}{
		{"major", `semver.major("1.2.3")`, int64(1)},
		{"minor", `semver.minor("1.2.3")`, int64(2)},
		{"patch", `semver.patch("1.2.3")`, int64(3)},
		{"major-double-digit", `semver.major("10.20.30")`, int64(10)},
		{"minor-double-digit", `semver.minor("10.20.30")`, int64(20)},
		{"patch-double-digit", `semver.patch("10.20.30")`, int64(30)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, tc.expr))
		})
	}
}

func TestMajorToString(t *testing.T) {
	t.Parallel()
	// CEL exposes int → string conversion; the "supports returning
	// string or number" behaviour is achieved by wrapping the int
	// accessor with the string() constructor.
	require.Equal(t, "1", run(t, `string(semver.major("1.2.3"))`))
}

func TestPrereleaseAndBuild(t *testing.T) {
	t.Parallel()
	require.Equal(t, "alpha.1", run(t, `semver.prerelease("1.2.3-alpha.1")`))
	require.Empty(t, run(t, `semver.prerelease("1.2.3")`))
	require.Equal(t, "sha.abc", run(t, `semver.build("1.2.3+sha.abc")`))
	require.Equal(t, "20130313144700", run(t, `semver.build("1.2.3-beta+20130313144700")`))
}

func TestComparisonPredicates(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		expr string
		want any
	}{
		{"isNewer-true", `semver.isNewer("1.2.3", "1.1.3")`, true},
		{"isNewer-false", `semver.isNewer("1.1.3", "1.2.3")`, false},
		{"isNewer-equal", `semver.isNewer("1.2.3", "1.2.3")`, false},
		{"isOlder-true", `semver.isOlder("1.1.3", "1.2.3")`, true},
		{"isOlder-false", `semver.isOlder("1.2.3", "1.1.3")`, false},
		{"equal-true", `semver.equal("1.2.3", "1.2.3")`, true},
		{"equal-false", `semver.equal("1.2.3", "1.2.4")`, false},

		// Prerelease-aware ordering: 1.0.0-alpha < 1.0.0.
		{"prerelease-older-than-release", `semver.isOlder("1.0.0-alpha", "1.0.0")`, true},
		{"prerelease-ordering", `semver.isNewer("1.0.0-beta", "1.0.0-alpha")`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, tc.expr))
		})
	}
}

func TestCompareReturns(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(1), run(t, `semver.compare("1.2.3", "1.1.3")`))
	require.Equal(t, int64(-1), run(t, `semver.compare("1.1.3", "1.2.3")`))
	require.Equal(t, int64(0), run(t, `semver.compare("1.2.3", "1.2.3")`))
}

func TestSatisfiesConstraints(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		expr string
		want any
	}{
		{"caret-match", `semver.satisfies("1.2.3", "^1.0.0")`, true},
		{"caret-miss", `semver.satisfies("2.0.0", "^1.0.0")`, false},
		{"range", `semver.satisfies("1.5.0", ">=1.0.0 <2.0.0")`, true},
		{"range-upper-exclusive", `semver.satisfies("2.0.0", ">=1.0.0 <2.0.0")`, false},
		{"tilde", `semver.satisfies("1.2.5", "~1.2.0")`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, tc.expr))
		})
	}
}

func TestValidationPredicates(t *testing.T) {
	t.Parallel()
	require.Equal(t, true, run(t, `semver.isValid("1.2.3")`))
	require.Equal(t, true, run(t, `semver.isValid("1.2.3-alpha+build")`))
	require.Equal(t, true, run(t, `semver.isValid("v1.2.3")`)) // leading v accepted
	require.Equal(t, false, run(t, `semver.isValid("not-a-version")`))

	require.Equal(t, true, run(t, `semver.isStable("1.2.3")`))
	require.Equal(t, false, run(t, `semver.isStable("0.9.0")`))     // pre-1.0 is not stable
	require.Equal(t, false, run(t, `semver.isStable("1.2.3-rc1")`)) // prerelease is not stable
}

func TestParseReturnsMap(t *testing.T) {
	t.Parallel()
	got := run(t, `semver.parse("1.2.3-alpha.1+sha.abc")`)
	m, ok := got.(map[string]any)
	require.True(t, ok, "parse result should be a map, got %T", got)

	require.Equal(t, int64(1), m["major"])
	require.Equal(t, int64(2), m["minor"])
	require.Equal(t, int64(3), m["patch"])
	require.Equal(t, "alpha.1", m["prerelease"])
	require.Equal(t, "sha.abc", m["build"])
	require.Equal(t, "1.2.3-alpha.1+sha.abc", m["original"])
}

func TestInvalidInputsReturnError(t *testing.T) {
	t.Parallel()
	p := New()
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)

	for _, expr := range []string{
		`semver.major("not-a-version")`,
		`semver.compare("1.2.3", "nope")`,
		`semver.satisfies("1.2.3", "not-a-constraint")`,
	} {
		ast, iss := env.Compile(expr)
		require.NoError(t, iss.Err(), "compile %q", expr)
		program, err := env.Program(ast)
		require.NoError(t, err)
		_, _, err = program.Eval(p.VarValues(nil, nil, nil))
		require.Error(t, err, "expected error for %q", expr)
	}
}
