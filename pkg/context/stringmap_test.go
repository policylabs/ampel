// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringMapGetValue(t *testing.T) {
	for _, tt := range []struct {
		name    string
		key     string
		expect  any
		mustErr bool
		sut     []string
	}{
		{
			name: "string-value", expect: "Hello I'm here", key: "test_ks", mustErr: false,
			sut: []string{"test_ks:Hello I'm here"},
		},
		{
			name: "number-value", expect: "1", key: "test_k", mustErr: false,
			sut: []string{"test_k:1"},
		},
		{
			name: "no-colon", expect: nil, key: "test_o", mustErr: false,
			sut: []string{"test_o"},
		},
		{
			name: "no-value", expect: "", key: "test_oo", mustErr: false,
			sut: []string{"test_oo:"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			//	t.Parallel()
			reader := StringMapList(tt.sut)
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

func TestNewStringMapList(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		vals    []string
		mustErr bool
	}{
		{name: "key-value", vals: []string{"builderId:https://github.com/org/repo/.github/workflows/release.yaml"}},
		{name: "value-with-colons", vals: []string{"buildPoint:git+ssh://github.com/org/repo@refs/heads/main"}},
		{name: "empty-value", vals: []string{"since:"}},
		{name: "dotted-key", vals: []string{"policy.v2:on"}},
		{name: "several", vals: []string{"a:1", "b:2"}},
		{name: "empty-list", vals: nil},
		{name: "equals-instead-of-colon", vals: []string{"builderId=https://github.com/org/repo"}, mustErr: true},
		{name: "no-colon", vals: []string{"builderId"}, mustErr: true},
		{name: "empty-key", vals: []string{":value"}, mustErr: true},
		{name: "space-in-key", vals: []string{"builder id:x"}, mustErr: true},
		{name: "one-bad-among-good", vals: []string{"a:1", "b=2"}, mustErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l, err := NewStringMapList(tt.vals)
			if tt.mustErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrInvalidContextValue)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, l)
		})
	}
}
