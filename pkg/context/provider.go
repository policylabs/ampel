// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
)

// Provider is an interface that abstracts objects that
// can extract contextual data data from a source. The
// API contract is pretty simple: If the source has a value
// ir returns it. If it does not returns nil. When asking
// for a map with specific keys, the map should not have an
// entry for a key it doesn't have a value for.
type Provider interface {
	GetContextValue(string) (any, error)
	GetContextMap(keys []string) (map[string]any, error)
}

// GetValues extracts the context values from a list of providers
func GetValues(providers []Provider, keys []string) (map[string]any, error) {
	ret := map[string]any{}
	maps := []map[string]any{}

	// Assemble the maps from all providers
	for _, p := range providers {
		m, err := p.GetContextMap(keys)
		if err != nil {
			return nil, fmt.Errorf("reading context data from provider: %w", err)
		}
		maps = append(maps, m)
	}

	// Return the first value found by trying the provider data
	// in the order they were loaded:
	for _, k := range keys {
		for _, mp := range maps {
			if v, ok := mp[k]; ok {
				ret[k] = v
				break
			}
		}
	}
	return ret, nil
}
