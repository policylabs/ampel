// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"testing"

	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/evaluator/cel"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

func TestSupportsVersion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		requested string
		supported string
		want      bool
	}{
		{"", "v0", true},
		{"v0", "v0", true},
		{"v1", "v0", false},
		{"v99", "v0", false},
		{"garbage", "v0", false},
		{"v1", "v1", true},
		{"v0", "v1", true},
	} {
		got := class.SupportsVersion(tc.requested, tc.supported)
		require.Equal(t, tc.want, got, "supportsVersion(%q, %q)", tc.requested, tc.supported)
	}
}

func TestFactoryVersionMismatch(t *testing.T) {
	t.Parallel()
	f := &Factory{}
	opts := &options.Default

	t.Run("supported version returns real evaluator", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel@v0"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.False(t, ok, "cel@v0 should return a real evaluator, not a stub")
	})

	t.Run("no version suffix returns real evaluator", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.False(t, ok, "cel (no version) should return a real evaluator")
	})

	t.Run("unsupported version returns stub", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel@v99"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.True(t, ok, "cel@v99 should return a versionMismatchEvaluator")
		require.Equal(t, cel.Class.Version(), e.SupportedVersion())
	})

	t.Run("stub ExecTenet returns FAIL with message", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel@v99"))
		require.NoError(t, err)
		result, err := e.ExecTenet(context.Background(), opts, &papi.Tenet{Id: "test-tenet"}, nil)
		require.NoError(t, err)
		require.Equal(t, papi.StatusFAIL, result.GetStatus())
		require.Contains(t, result.GetError().GetMessage(), "cel@v99")
		require.Contains(t, result.GetError().GetMessage(), cel.Class.String())
		require.Equal(t, "test-tenet", result.GetId())
	})

	t.Run("satisfied plugin requirement returns real evaluator", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel@v0?plugin:semver=v0"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.False(t, ok, "cel@v0?plugin:semver=v0 should return a real evaluator")
	})

	t.Run("unsatisfied plugin version returns stub", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel@v0?plugin:semver=v99"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.True(t, ok, "cel@v0?plugin:semver=v99 should return a versionMismatchEvaluator")
		result, err := e.ExecTenet(context.Background(), opts, &papi.Tenet{Id: "t"}, nil)
		require.NoError(t, err)
		require.Equal(t, papi.StatusFAIL, result.GetStatus())
		require.Contains(t, result.GetError().GetMessage(), "semver")
		require.Contains(t, result.GetError().GetMessage(), "v99")
	})

	t.Run("unknown plugin name returns stub", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel@v0?plugin:nosuchplugin=v0"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.True(t, ok, "unknown plugin should return a versionMismatchEvaluator")
	})

	t.Run("unknown runtime name returns error", func(t *testing.T) {
		t.Parallel()
		_, err := f.Get(opts, class.MustParseClass("unknown@v0"))
		require.Error(t, err)
	})

	t.Run("all plugins satisfied returns real evaluator", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel@v0?plugin:semver=v0&plugin:purl=v0"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.False(t, ok, "all satisfied plugins should return a real evaluator")
	})

	t.Run("one unsatisfied plugin among multiple returns stub", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel@v0?plugin:semver=v0&plugin:purl=v99"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.True(t, ok, "one unsatisfied plugin should return a versionMismatchEvaluator")
		result, err := e.ExecTenet(context.Background(), opts, &papi.Tenet{Id: "t"}, nil)
		require.NoError(t, err)
		require.Equal(t, papi.StatusFAIL, result.GetStatus())
		require.Contains(t, result.GetError().GetMessage(), "purl")
		require.Contains(t, result.GetError().GetMessage(), "v99")
	})

	t.Run("transformer requirement does not block evaluator", func(t *testing.T) {
		t.Parallel()
		// Transformer requirements in the class string are not yet checked at the
		// evaluator factory level. A class with only a transformer requirement should
		// still return a usable evaluator.
		e, err := f.Get(opts, class.MustParseClass("cel@v0?transformer:protobom=v0"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.False(t, ok, "transformer-only requirement should not block the evaluator")
	})

	t.Run("plugin and transformer combined returns real evaluator when plugin satisfied", func(t *testing.T) {
		t.Parallel()
		e, err := f.Get(opts, class.MustParseClass("cel@v0?plugin:semver=v0&transformer:protobom=v0"))
		require.NoError(t, err)
		_, ok := e.(*versionMismatchEvaluator)
		require.False(t, ok, "satisfied plugin with transformer requirement should return a real evaluator")
	})
}

func TestFactorySkipUnsupportedRuntime(t *testing.T) {
	t.Parallel()
	f := &Factory{}

	skipOpts := options.Default
	skipOpts.SkipUnsupportedRuntime = true

	// Each case declares a runtime this engine cannot satisfy. With the skip
	// option on, the stub soft-fails the tenet; with it off (options.Default),
	// the stub fails it.
	for _, tc := range []struct {
		name  string
		class string
	}{
		{"unsupported engine version", "cel@v99"},
		{"missing plugin", "cel@v0?plugin:nosuchplugin=v0"},
		{"plugin version too new", "cel@v0?plugin:semver=v99"},
	} {
		t.Run(tc.name+" soft-fails when skipping", func(t *testing.T) {
			t.Parallel()
			e, err := f.Get(&skipOpts, class.MustParseClass(tc.class))
			require.NoError(t, err)
			result, err := e.ExecTenet(context.Background(), &skipOpts, &papi.Tenet{Id: "t"}, nil)
			require.NoError(t, err)
			require.Equal(t, papi.StatusSOFTFAIL, result.GetStatus(), "skip option should soft-fail unsupported runtime")
			require.NotEmpty(t, result.GetError().GetMessage(), "the skipped result should still explain why")
		})

		t.Run(tc.name+" fails by default", func(t *testing.T) {
			t.Parallel()
			e, err := f.Get(&options.Default, class.MustParseClass(tc.class))
			require.NoError(t, err)
			result, err := e.ExecTenet(context.Background(), &options.Default, &papi.Tenet{Id: "t"}, nil)
			require.NoError(t, err)
			require.Equal(t, papi.StatusFAIL, result.GetStatus(), "default behavior should fail unsupported runtime")
		})
	}
}
