// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"testing"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func TestHasher(t *testing.T) {
	t.Parallel()
	u := New()
	env, err := cel.NewEnv(
		u.Library(),
	)
	require.NoError(t, err)

	t.Run("parse", func(t *testing.T) {
		t.Parallel()
		ast, iss := env.Compile("url.parse(\"https://example.com/chido#adios\")")
		require.NoError(t, iss.Err())

		program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		require.NoError(t, err)

		result, _, err := program.Eval(u.VarValues(nil, nil, nil))
		require.NoError(t, err)
		require.Equal(t, map[string]string{"fragment": "adios", "host": "example.com", "path": "/chido", "scheme": "https"}, result.Value())
	})
}
