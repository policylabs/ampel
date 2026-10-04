// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetValues(t *testing.T) {
	p1 := StringMapList([]string{"val1:b"})
	p2 := StringMapList([]string{"val1:a", "val2:2"})

	t.Parallel()
	for _, tt := range []struct {
		name      string
		providers []Provider
		keys      []string
		expect    map[string]any
		mustErr   bool
	}{
		{
			name:      "one",
			providers: []Provider{&p1},
			keys:      []string{"val1"},
			expect:    map[string]any{"val1": "b"},
		},
		{
			name:      "override",
			providers: []Provider{&p2, &p1},
			keys:      []string{"val1"},
			expect:    map[string]any{"val1": "a"},
		},
		{
			name:      "non-existent",
			providers: []Provider{&p2, &p1},
			keys:      []string{"valX"},
			expect:    map[string]any{},
		},
		{
			name:      "exists-only-in-second",
			providers: []Provider{&p1, &p2},
			keys:      []string{"val2"},
			expect:    map[string]any{"val2": "2"},
		},
		{
			name:      "one-from-each",
			providers: []Provider{&p1, &p2},
			keys:      []string{"val1", "val2"},
			expect:    map[string]any{"val1": "b", "val2": "2"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ret, err := GetValues(tt.providers, tt.keys)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expect, ret)
		})
	}
}

// TestGetValuesMultiSource tests that context values from different provider
// types (JSON, YAML, string map, env) merge correctly with the expected
// precedence: earlier providers win.
func TestGetValuesMultiSource(t *testing.T) {
	t.Parallel()
	// JSON provider: has "name" and "format"
	jsonProvider, err := NewProviderFromJSON(strings.NewReader(
		`{"name": "from-json", "format": "json"}`,
	))
	require.NoError(t, err)

	// YAML provider: has "name" (should be shadowed) and "source"
	yamlProvider, err := NewProviderFromYAML(strings.NewReader(
		"name: from-yaml\nsource: yaml-file",
	))
	require.NoError(t, err)

	// String map provider: has "env" and "name" (should be shadowed by both above)
	strProvider := StringMapList([]string{"env:production", "name:from-string"})

	for _, tt := range []struct {
		name      string
		providers []Provider
		keys      []string
		expect    map[string]any
	}{
		{
			name:      "json-wins-over-yaml",
			providers: []Provider{jsonProvider, yamlProvider},
			keys:      []string{"name"},
			expect:    map[string]any{"name": "from-json"},
		},
		{
			name:      "yaml-wins-over-json",
			providers: []Provider{yamlProvider, jsonProvider},
			keys:      []string{"name"},
			expect:    map[string]any{"name": "from-yaml"},
		},
		{
			name:      "each-provider-contributes",
			providers: []Provider{jsonProvider, yamlProvider, &strProvider},
			keys:      []string{"name", "source", "env"},
			expect:    map[string]any{"name": "from-json", "source": "yaml-file", "env": "production"},
		},
		{
			name:      "key-from-last-provider-only",
			providers: []Provider{jsonProvider, yamlProvider, &strProvider},
			keys:      []string{"env"},
			expect:    map[string]any{"env": "production"},
		},
		{
			name:      "missing-key-across-all",
			providers: []Provider{jsonProvider, yamlProvider, &strProvider},
			keys:      []string{"nonexistent"},
			expect:    map[string]any{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ret, err := GetValues(tt.providers, tt.keys)
			require.NoError(t, err)
			require.Equal(t, tt.expect, ret)
		})
	}
}
