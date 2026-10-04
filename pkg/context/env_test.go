// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// This test cannot be run in parallel because of setenv
func TestEnvGetValue(t *testing.T) {
	for _, tt := range []struct {
		name    string
		key     string
		expect  string
		mustErr bool
		setup   func(*testing.T, *EnvContextReader)
	}{
		{
			name: "normal-value", expect: "hello", key: "test_func1", mustErr: false,
			setup: func(t *testing.T, _ *EnvContextReader) {
				t.Helper()
				t.Setenv("AMPEL_TEST_FUNC1", "hello")
			},
		},
		{
			name: "othercase", expect: "hello", key: "Test_FUNC2", mustErr: false,
			setup: func(t *testing.T, _ *EnvContextReader) {
				t.Helper()
				t.Setenv("AMPEL_TEST_FUNC2", "hello")
			},
		},
		{
			name: "empty-key", key: "", mustErr: true,
			setup: func(t *testing.T, _ *EnvContextReader) {
				t.Helper()
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			//	t.Parallel()
			reader := NewEnvContextReader()
			tt.setup(t, reader)
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
