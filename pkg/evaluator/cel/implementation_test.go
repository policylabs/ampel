// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"os"
	"testing"

	"cel.dev/cel-go/cel"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/collector/predicate"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/evaluator/evalcontext"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

func TestEvaluateChainedSelector(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		code           string
		predicatePath  string
		expectedLength int
		expected       *intoto.ResourceDescriptor
		mustErr        bool
	}{
		{"slsa", "predicate.data.materials[0]", "testdata/slsa-v0.2.json", 1, &intoto.ResourceDescriptor{
			Uri:    "git+https://github.com/slsa-framework/slsa-verifier@refs/tags/v2.6.0",
			Digest: map[string]string{"sha1": "3714a2a4684014deb874a0e737dffa0ee02dd647", "gitCommit": "3714a2a4684014deb874a0e737dffa0ee02dd647"},
		}, false},
		{"string", "\"sha1:\"+predicate.data.materials[0].digest[\"sha1\"]", "testdata/slsa-v0.2.json", 1, &intoto.ResourceDescriptor{
			Digest: map[string]string{"sha1": "3714a2a4684014deb874a0e737dffa0ee02dd647"},
		}, false},
		{"bad-string", "\"bad string\"", "testdata/slsa-v0.2.json", 1, nil, true},
		{"bad-structure", "[1,2,3]", "testdata/slsa-v0.2.json", 1, nil, true},
	} {
		ev := &defaulCelEvaluator{}

		env, err := ev.CreateEnvironment(nil, nil)
		require.NoError(t, err)

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(tc.predicatePath)
			require.NoError(t, err)

			// Load the predicate from file
			pred, err := predicate.Parsers.Parse(data)
			require.NoError(t, err)

			// Compile the code
			ast, err := ev.CompileCode(env, tc.code)
			require.NoError(t, err)

			vars, err := ev.BuildSelectorVariables(&options.EvaluatorOptions{}, nil, &evalcontext.EvaluationContext{}, nil, nil, nil, pred)
			require.NoError(t, err)

			res, err := ev.EvaluateChainedSelector(env, ast, vars)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Len(t, res, tc.expectedLength)
			require.Equal(t, tc.expected.GetUri(), res[0].GetUri())
			require.Equal(t, tc.expected.GetName(), res[0].GetName())
			require.Equal(t, tc.expected.GetDigest(), res[0].GetDigest())
		})
	}
}

// TestOptionalOperators verifies that the CEL environment has OptionalTypes
// enabled. The test uses the SLSA v0.2 predicate fixture where materials[1]
// has no digest field, making it a natural fit for chained optional access\.
func TestOptionalOperators(t *testing.T) {
	t.Parallel()
	ev := &defaulCelEvaluator{}

	env, err := ev.CreateEnvironment(nil, nil)
	require.NoError(t, err)

	data, err := os.ReadFile("testdata/slsa-v0.2.json")
	require.NoError(t, err)

	pred, err := predicate.Parsers.Parse(data)
	require.NoError(t, err)

	vars, err := ev.BuildSelectorVariables(&options.EvaluatorOptions{}, nil, &evalcontext.EvaluationContext{}, nil, nil, nil, pred)
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		code     string
		expected any
	}{
		{
			// materials[0] has a digest — the chain resolves to the sha1 value.
			name:     "present chain resolves to value",
			code:     `predicate.data.materials[0].?digest.sha1.orValue("not-present")`,
			expected: "3714a2a4684014deb874a0e737dffa0ee02dd647",
		},
		{
			// materials[1] has no digest — optional propagates through .sha1 to the default.
			name:     "absent intermediate returns default",
			code:     `predicate.data.materials[1].?digest.sha1.orValue("not-present")`,
			expected: "not-present",
		},
		{
			name:     "hasValue true when field present",
			code:     `predicate.data.materials[0].?digest.hasValue()`,
			expected: true,
		},
		{
			name:     "hasValue false when field absent",
			code:     `predicate.data.materials[1].?digest.hasValue()`,
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ast, err := ev.CompileCode(env, tc.code)
			require.NoError(t, err)

			got, err := ev.EvaluateExpression(env, ast, vars)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

// TestLazyExprMap verifies that a lazyExprMap evaluates entries on first
// reference, that entries can reference siblings via both dot and bracket
// notation, that cycles are detected and reported as errors, and that
// unreferenced entries are absent from the snapshot.
func TestLazyExprMap(t *testing.T) {
	t.Parallel()
	ev := &defaulCelEvaluator{}

	env, err := ev.CreateEnvironment(nil, nil)
	require.NoError(t, err)

	for _, tc := range []struct {
		name       string
		outputs    map[string]string
		mainCode   string
		wantVal    any
		wantErr    string
		wantSnap   []string
		absentSnap []string
	}{
		{
			name: "dot notation cross-reference resolves correctly",
			outputs: map[string]string{
				"a": `"hello"`,
				"b": `outputs.a + " world"`,
			},
			mainCode: `outputs.b == "hello world"`,
			wantVal:  true,
		},
		{
			name: "bracket notation also resolves correctly",
			outputs: map[string]string{
				"a": `"hello"`,
				"b": `outputs.a + " world"`,
			},
			mainCode: `outputs["b"] == "hello world"`,
			wantVal:  true,
		},
		{
			name: "cycle detection returns error",
			outputs: map[string]string{
				"cycleA": `outputs.cycleB`,
				"cycleB": `outputs.cycleA`,
			},
			mainCode: `outputs.cycleA`,
			wantErr:  "cycle",
		},
		{
			name: "unreferenced output absent from snapshot",
			outputs: map[string]string{
				"a":      `"hello"`,
				"b":      `outputs.a + " world"`,
				"unused": `"never evaluated"`,
			},
			mainCode:   `outputs.b == "hello world"`,
			wantSnap:   []string{"a", "b"},
			absentSnap: []string{"unused"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			asts := make(map[string]*cel.Ast, len(tc.outputs))
			for name, code := range tc.outputs {
				ast, err := ev.CompileCode(env, code)
				require.NoError(t, err)
				asts[name] = ast
			}

			vars := map[string]any{}
			lazy := newLazyExprMap(env, asts, vars)
			vars[VarNameOutputs] = lazy

			mainAst, err := ev.CompileCode(env, tc.mainCode)
			require.NoError(t, err)

			got, err := ev.EvaluateExpression(env, mainAst, &vars)
			if tc.wantErr != "" {
				require.Error(t, err, "expected evaluation error containing %q", tc.wantErr)
				require.Contains(t, err.Error(), tc.wantErr, "error message mismatch")
				return
			}
			require.NoError(t, err)

			if tc.wantVal != nil {
				require.Equal(t, tc.wantVal, got, "evaluation result mismatch")
			}

			snap := lazy.snapshot()
			for _, k := range tc.wantSnap {
				require.Contains(t, snap, k, "expected %q in snapshot", k)
			}
			for _, k := range tc.absentSnap {
				require.NotContains(t, snap, k, "expected %q absent from snapshot", k)
			}
		})
	}
}
