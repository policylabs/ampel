// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMapAnyGetValue(t *testing.T) {
	for _, tt := range []struct {
		name    string
		key     string
		expect  any
		mustErr bool
		sut     map[string]any
	}{
		{
			name: "normal-value", expect: "hai", key: "test_func1", mustErr: false,
			sut: map[string]any{"test_func1": "hai"},
		},
		{
			name: "not-set", expect: nil, key: "other_key", mustErr: false,
			sut: map[string]any{"test_func1": "hai"},
		},
		{
			name: "nil-map", expect: nil, key: "other_key", mustErr: false,
			sut: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			//	t.Parallel()
			reader := MapAnyProvider(tt.sut)
			res, err := reader.GetContextValue(tt.key)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expect, res)
		})
	}
}

func TestNewProviderFromJSON(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		input   string
		key     string
		expect  any
		mustErr bool
	}{
		{
			name:   "string-value",
			input:  `{"greeting": "hello"}`,
			key:    "greeting",
			expect: "hello",
		},
		{
			name:   "numeric-value",
			input:  `{"count": 42}`,
			key:    "count",
			expect: float64(42),
		},
		{
			name:   "boolean-value",
			input:  `{"enabled": true}`,
			key:    "enabled",
			expect: true,
		},
		{
			name:   "missing-key",
			input:  `{"key": "val"}`,
			key:    "other",
			expect: nil,
		},
		{
			name:    "invalid-json",
			input:   `not json`,
			mustErr: true,
		},
		{
			name:    "json-array-not-object",
			input:   `["a", "b"]`,
			mustErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			provider, err := NewProviderFromJSON(strings.NewReader(tt.input))
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			val, err := provider.GetContextValue(tt.key)
			require.NoError(t, err)
			require.Equal(t, tt.expect, val)
		})
	}
}

func TestNewProviderFromJSONFile(t *testing.T) {
	t.Parallel()
	t.Run("valid-file", func(t *testing.T) {
		t.Parallel()
		provider, err := NewProviderFromJSONFile("testdata/context.json")
		require.NoError(t, err)

		val, err := provider.GetContextValue("name")
		require.NoError(t, err)
		require.Equal(t, "test-project", val)
	})

	t.Run("nonexistent-file", func(t *testing.T) {
		t.Parallel()
		_, err := NewProviderFromJSONFile("testdata/does-not-exist.json")
		require.Error(t, err)
	})
}

func TestNewProviderFromYAML(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		input   string
		key     string
		expect  any
		mustErr bool
	}{
		{
			name:   "string-value",
			input:  "greeting: hello",
			key:    "greeting",
			expect: "hello",
		},
		{
			name:   "numeric-value",
			input:  "count: 42",
			key:    "count",
			expect: 42,
		},
		{
			name:   "boolean-value",
			input:  "enabled: true",
			key:    "enabled",
			expect: true,
		},
		{
			name:   "missing-key",
			input:  "key: val",
			key:    "other",
			expect: nil,
		},
		{
			name:    "invalid-yaml",
			input:   ":\n  :\n    - :\n  bad:\n [",
			mustErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			provider, err := NewProviderFromYAML(strings.NewReader(tt.input))
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			val, err := provider.GetContextValue(tt.key)
			require.NoError(t, err)
			require.Equal(t, tt.expect, val)
		})
	}
}

func TestNewProviderFromYAMLFile(t *testing.T) {
	t.Parallel()
	t.Run("valid-file", func(t *testing.T) {
		t.Parallel()
		provider, err := NewProviderFromYAMLFile("testdata/context.yaml")
		require.NoError(t, err)

		val, err := provider.GetContextValue("name")
		require.NoError(t, err)
		require.Equal(t, "test-project", val)
	})

	t.Run("nonexistent-file", func(t *testing.T) {
		t.Parallel()
		_, err := NewProviderFromYAMLFile("testdata/does-not-exist.yaml")
		require.Error(t, err)
	})
}

// TestJSONYAMLConsistency verifies that the same structured data loaded from
// JSON and YAML produces identical context values. This ensures users can
// switch between formats without behavioral differences.
func TestJSONYAMLConsistency(t *testing.T) {
	t.Parallel()

	jsonProvider, err := NewProviderFromJSONFile("testdata/context.json")
	require.NoError(t, err)

	yamlProvider, err := NewProviderFromYAMLFile("testdata/context.yaml")
	require.NoError(t, err)

	keys := []string{"name", "enabled", "tags", "nested"}

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			jVal, err := jsonProvider.GetContextValue(key)
			require.NoError(t, err)

			yVal, err := yamlProvider.GetContextValue(key)
			require.NoError(t, err)

			require.Equal(t, jVal, yVal, "value mismatch for key %q between JSON and YAML providers", key)
		})
	}

	// Also verify GetContextMap returns the same results
	t.Run("context-map", func(t *testing.T) {
		t.Parallel()
		jMap, err := jsonProvider.GetContextMap(keys)
		require.NoError(t, err)

		yMap, err := yamlProvider.GetContextMap(keys)
		require.NoError(t, err)

		require.Equal(t, jMap, yMap)
	})
}
