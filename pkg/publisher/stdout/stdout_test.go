// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package stdout

import (
	"bytes"
	"context"
	"testing"

	papi "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/ampel/pkg/publisher"
)

func TestRegisterAndFromString(t *testing.T) {
	t.Parallel()
	require.NoError(t, publisher.RegisterEmitterType(TypeMoniker, Build))
	t.Cleanup(func() { publisher.UnregisterEmitterType(TypeMoniker) })

	e, err := publisher.EmitterFromString(TypeMoniker + ":")
	require.NoError(t, err)
	require.IsType(t, &Emitter{}, e)
}

func TestEmit(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	e := &Emitter{Writer: &buf}

	rs := &papi.ResultSet{
		PolicySet: &papi.PolicyRef{Id: "test-set"},
		Status:    papi.StatusPASS,
	}
	require.NoError(t, e.Emit(context.Background(), rs))
	require.Contains(t, buf.String(), "test-set")
}
