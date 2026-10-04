// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"slices"
	"testing"

	"cel.dev/cel-go/cel"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

func TestHasher(t *testing.T) {
	t.Parallel()
	h := New()
	env, err := cel.NewEnv(
		h.Library(),
	)
	require.NoError(t, err)

	t.Run("algos", func(t *testing.T) {
		t.Parallel()
		ast, iss := env.Compile("hashAlgorithms")
		require.NoError(t, iss.Err())

		program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		require.NoError(t, err)

		result, _, err := program.Eval(h.VarValues(nil, nil, nil))
		require.NoError(t, err)

		require.NotNil(t, result)
		official := make([]string, 0, len(intoto.HashAlgorithms))
		for algo := range intoto.HashAlgorithms {
			official = append(official, algo)
		}
		got, ok := result.Value().([]string)
		require.True(t, ok)
		slices.Sort(official)
		slices.Sort(got)

		require.Equal(t, official, got)
	})

	t.Run("sha256", func(t *testing.T) {
		t.Parallel()
		ast, iss := env.Compile("hasher.sha256(\"test\")")
		require.NoError(t, iss.Err())

		program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		require.NoError(t, err)

		result, _, err := program.Eval(h.VarValues(nil, nil, nil))
		require.NoError(t, err)
		require.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", result.Value())
	})

	t.Run("sha512", func(t *testing.T) {
		t.Parallel()
		ast, iss := env.Compile("hasher.sha512(\"test\")")
		require.NoError(t, iss.Err())

		program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		require.NoError(t, err)

		result, _, err := program.Eval(h.VarValues(nil, nil, nil))
		require.NoError(t, err)
		require.Equal(t, "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", result.Value())
	})

	t.Run("sha1", func(t *testing.T) {
		t.Parallel()
		ast, iss := env.Compile("hasher.sha1(\"test\")")
		require.NoError(t, iss.Err())

		program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		require.NoError(t, err)

		result, _, err := program.Eval(h.VarValues(nil, nil, nil))
		require.NoError(t, err)
		require.Equal(t, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", result.Value())
	})
}
