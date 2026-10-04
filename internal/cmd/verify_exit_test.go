// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/stretchr/testify/require"
)

func TestExitNonZero(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		status   string
		exitCode bool
		failSkip bool
		expect   bool
	}{
		{"pass", papi.StatusPASS, true, true, false},
		{"softfail", papi.StatusSOFTFAIL, true, true, false},
		{"fail-with-exit-code", papi.StatusFAIL, true, false, true},
		{"fail-without-exit-code", papi.StatusFAIL, false, true, false},
		{"skip-by-default", papi.StatusSKIP, true, false, false},
		{"skip-with-fail-skip", papi.StatusSKIP, true, true, true},
		{"exit-code-off-disables-fail-skip", papi.StatusSKIP, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := &verifyOptions{FailSkip: tc.failSkip}
			opts.SetExitCode = tc.exitCode
			require.Equal(t, tc.expect, opts.exitNonZero(tc.status))
		})
	}
}
