// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package publisher

import (
	"context"
	"errors"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/stretchr/testify/require"
)

// capture is a minimal Emitter that records what it was given and can be made
// to fail on demand.
type capture struct {
	spec    string
	emitted papi.Results
	err     error
}

func (c *capture) Emit(_ context.Context, r papi.Results, _ ...EmitOpt) error {
	c.emitted = r
	return c.err
}

func TestEmitterFromString(t *testing.T) {
	t.Parallel()
	require.NoError(t, RegisterEmitterType("test-from-string", func(spec string) (Emitter, error) {
		return &capture{spec: spec}, nil
	}))
	t.Cleanup(func() { UnregisterEmitterType("test-from-string") })

	for _, tc := range []struct {
		name     string
		init     string
		mustErr  bool
		wantSpec string
	}{
		{name: "no-spec", init: "test-from-string:", wantSpec: ""},
		{name: "plain-uri", init: "test-from-string:https://example.com/hook", wantSpec: "https://example.com/hook"},
		{
			// The spec reaches the factory verbatim: a query string must
			// survive, never split into key=value config.
			name:     "uri-with-query",
			init:     "test-from-string:https://host/hook?token=abc",
			wantSpec: "https://host/hook?token=abc",
		},
		{name: "no-colon", init: "no-colon", mustErr: true},
		{name: "empty-moniker", init: ":https://example.com", mustErr: true},
		{name: "unknown-moniker", init: "does-not-exist:https://example.com", mustErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := EmitterFromString(tc.init)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			c, ok := e.(*capture)
			require.True(t, ok)
			require.Equal(t, tc.wantSpec, c.spec)
		})
	}
}

func TestRegisterEmitterType(t *testing.T) {
	t.Parallel()
	factory := func(string) (Emitter, error) { return &capture{}, nil }
	require.NoError(t, RegisterEmitterType("test-register", factory))
	t.Cleanup(func() { UnregisterEmitterType("test-register") })

	// A second registration of the same moniker is rejected.
	require.ErrorIs(t, RegisterEmitterType("test-register", factory), ErrTypeAlreadyRegistered)

	// After unregistering, it can be registered again.
	UnregisterEmitterType("test-register")
	require.NoError(t, RegisterEmitterType("test-register", factory))
}

func TestPublisherBuild(t *testing.T) {
	t.Parallel()
	var gotSpec string
	require.NoError(t, RegisterEmitterType("test-build", func(spec string) (Emitter, error) {
		gotSpec = spec
		return &capture{}, nil
	}))
	t.Cleanup(func() { UnregisterEmitterType("test-build") })

	p := New()
	p.AddEmitterInit("test-build:https://host/x?token=abc")
	require.NoError(t, p.Build())
	require.Len(t, p.Emitters, 1)
	require.Equal(t, "https://host/x?token=abc", gotSpec)

	// The init queue is consumed: a second Build adds nothing.
	require.NoError(t, p.Build())
	require.Len(t, p.Emitters, 1)
}

func TestPublisherBuildUnknownType(t *testing.T) {
	t.Parallel()
	p := New()
	p.AddEmitterInit("does-not-exist:spec")
	require.Error(t, p.Build())
}

func TestPublishResults(t *testing.T) {
	t.Parallel()
	good := &capture{}
	bad := &capture{err: errors.New("boom")}
	p := New()
	p.AddEmitter(good, bad)

	rs := &papi.ResultSet{Status: papi.StatusPASS}
	err := p.PublishResults(context.Background(), rs)
	require.ErrorContains(t, err, "boom")
	// Every emitter is invoked even though one failed.
	require.NotNil(t, good.emitted)
	require.NotNil(t, bad.emitted)
}

func TestPublishResultsNil(t *testing.T) {
	t.Parallel()
	p := New()
	p.AddEmitter(&capture{})
	require.NoError(t, p.PublishResults(context.Background(), nil))
}

func TestLoadsDefaults(t *testing.T) {
	t.Parallel()
	p := New()
	require.True(t, p.LoadsDefaults())
	p.SetLoadDefaults(false)
	require.False(t, p.LoadsDefaults())
}
