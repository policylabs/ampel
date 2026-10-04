// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package purl

import (
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func TestPurlParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		celExpr        string
		expectedFields map[string]any
	}{
		{
			name:    "complete PURL",
			celExpr: `purl.parse("pkg:golang/github.com/package-url/packageurl-go@v0.1.3")`,
			expectedFields: map[string]any{
				"type":      "golang",
				"namespace": "github.com/package-url",
				"name":      "packageurl-go",
				"version":   "v0.1.3",
				"subpath":   "",
			},
		},
		{
			name:    "PURL with qualifiers",
			celExpr: `purl.parse("pkg:npm/express@4.17.1?arch=x86_64&os=linux")`,
			expectedFields: map[string]any{
				"type":    "npm",
				"name":    "express",
				"version": "4.17.1",
			},
		},
		{
			name:    "PURL with subpath",
			celExpr: `purl.parse("pkg:golang/github.com/gorilla/mux@v1.8.0#pkg/mux")`,
			expectedFields: map[string]any{
				"type":      "golang",
				"namespace": "github.com/gorilla",
				"name":      "mux",
				"version":   "v1.8.0",
				"subpath":   "pkg/mux",
			},
		},
	}

	p := New()
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ast, iss := env.Compile(tt.celExpr)
			require.NoError(t, iss.Err())

			program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			result, _, err := program.Eval(p.VarValues(nil, nil, nil))
			require.NoError(t, err)

			resultMap, ok := result.Value().(map[string]any)
			require.True(t, ok, "result should be a map[string]any")
			for key, expectedValue := range tt.expectedFields {
				require.Equal(t, expectedValue, resultMap[key], "field %s mismatch", key)
			}
		})
	}
}

func TestPurlFieldExtractors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		celExpr       string
		expectedValue any
		checkType     string // "string", "map", "empty_map"
	}{
		{
			name:          "packageType - extract package type",
			celExpr:       `purl.packageType("pkg:npm/express@4.17.1")`,
			expectedValue: "npm",
			checkType:     "string",
		},
		{
			name:          "namespace - extract namespace",
			celExpr:       `purl.namespace("pkg:maven/org.springframework/spring-core@5.3.9")`,
			expectedValue: "org.springframework",
			checkType:     "string",
		},
		{
			name:          "namespace - empty namespace",
			celExpr:       `purl.namespace("pkg:npm/express@4.17.1")`,
			expectedValue: "",
			checkType:     "string",
		},
		{
			name:          "name - extract package name",
			celExpr:       `purl.name("pkg:npm/express@4.17.1")`,
			expectedValue: "express",
			checkType:     "string",
		},
		{
			name:          "version - extract version",
			celExpr:       `purl.version("pkg:npm/express@4.17.1")`,
			expectedValue: "4.17.1",
			checkType:     "string",
		},
		{
			name:          "version - no version",
			celExpr:       `purl.version("pkg:npm/express")`,
			expectedValue: "",
			checkType:     "string",
		},
		{
			name:    "qualifiers - extract qualifiers",
			celExpr: `purl.qualifiers("pkg:npm/express@4.17.1?arch=x86_64&os=linux")`,
			expectedValue: map[string]string{
				"arch": "x86_64",
				"os":   "linux",
			},
			checkType: "map",
		},
		{
			name:          "qualifiers - no qualifiers",
			celExpr:       `purl.qualifiers("pkg:npm/express@4.17.1")`,
			expectedValue: nil,
			checkType:     "empty_map",
		},
		{
			name:          "subpath - extract subpath",
			celExpr:       `purl.subpath("pkg:golang/github.com/gorilla/mux@v1.8.0#pkg/mux")`,
			expectedValue: "pkg/mux",
			checkType:     "string",
		},
		{
			name:          "subpath - no subpath",
			celExpr:       `purl.subpath("pkg:npm/express@4.17.1")`,
			expectedValue: "",
			checkType:     "string",
		},
	}

	p := New()
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ast, iss := env.Compile(tt.celExpr)
			require.NoError(t, iss.Err())

			program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			result, _, err := program.Eval(p.VarValues(nil, nil, nil))
			require.NoError(t, err)

			switch tt.checkType {
			case "string":
				require.Equal(t, tt.expectedValue, result.Value())
			case "map":
				qualMap, ok := result.Value().(map[string]string)
				require.True(t, ok, "result should be a map[string]string")
				expectedMap, ok := tt.expectedValue.(map[string]string)
				require.True(t, ok, "expectedValue should be a map[string]string")
				for key, expectedVal := range expectedMap {
					require.Equal(t, expectedVal, qualMap[key], "qualifier %s mismatch", key)
				}
			case "empty_map":
				qualMap, ok := result.Value().(map[string]string)
				require.True(t, ok, "result should be a map[string]string")
				require.Empty(t, qualMap)
			}
		})
	}
}

func TestPurlInvalidInput(t *testing.T) {
	t.Parallel()

	p := New()
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)

	// Test that parsing an invalid PURL results in a policy that returns an error
	ast, iss := env.Compile(`purl.packageType("not-a-valid-purl") == "npm"`)
	require.NoError(t, iss.Err())

	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	require.NoError(t, err)

	// Evaluation should succeed but return false or error during execution
	result, _, err := program.Eval(p.VarValues(nil, nil, nil))
	// CEL may return an error or an error value, either is acceptable
	if err == nil {
		// Check if result is an error type
		require.Contains(t, result.Type().TypeName(), "Error")
	}
}

func TestPurlPolicyScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		celExpr       string
		expectedValue bool
	}{
		{
			name:          "filter by type",
			celExpr:       `purl.packageType("pkg:maven/org.springframework/spring-core@5.3.9") == "maven"`,
			expectedValue: true,
		},
		{
			name:          "check version exists",
			celExpr:       `purl.version("pkg:npm/express@4.17.1") != ""`,
			expectedValue: true,
		},
		{
			name:          "namespace restriction",
			celExpr:       `purl.namespace("pkg:maven/org.springframework/spring-core@5.3.9") in ["org.springframework", "com.google"]`,
			expectedValue: true,
		},
		{
			name:          "parse and access fields",
			celExpr:       `purl.parse("pkg:golang/github.com/package-url/packageurl-go@v0.1.3")["type"] == "golang"`,
			expectedValue: true,
		},
		{
			name:          "check qualifiers",
			celExpr:       `has(purl.qualifiers("pkg:npm/express@4.17.1?arch=x86_64").arch)`,
			expectedValue: true,
		},
	}

	p := New()
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ast, iss := env.Compile(tt.celExpr)
			require.NoError(t, iss.Err())

			program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
			require.NoError(t, err)

			result, _, err := program.Eval(p.VarValues(nil, nil, nil))
			require.NoError(t, err)
			require.Equal(t, tt.expectedValue, result.Value())
		})
	}
}
