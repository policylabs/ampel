// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A bare "ampel verify" still verifies an artifact: anything that is not
// the name of a subcommand is its subject, while "artifact" routes to the
// explicit subcommand.
func TestVerifySubcommandRouting(t *testing.T) {
	t.Parallel()
	const digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for _, tc := range []struct {
		args     []string
		wantName string
	}{
		{[]string{digest}, "verify"},
		{[]string{"./some-file"}, "verify"},
		{[]string{}, "verify"},
		{[]string{"artifact", "./some-file"}, "artifact"},
		{[]string{"artifact", digest}, "artifact"},
	} {
		cmd, _ := newVerifyCommand()
		found, _, err := cmd.Find(tc.args)
		require.NoError(t, err)
		require.Equal(t, tc.wantName, found.Name(), "args %v", tc.args)
	}
}

// The artifact subcommand reads its subject the same way the bare verify
// command does, and both bind to the same options.
func TestVerifyArtifactSubject(t *testing.T) {
	t.Parallel()
	const digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	cmd, opts := newVerifyCommand()
	artifactCmd, args, err := cmd.Find([]string{"artifact", digest})
	require.NoError(t, err)
	require.NoError(t, artifactCmd.PreRunE(artifactCmd, args))
	require.Equal(t, subjectArtifact, opts.SubjectKind)
	require.Equal(t, digest, opts.SubjectHash)
	require.Empty(t, opts.SubjectFile)

	file := filepath.Join(t.TempDir(), "artifact.bin")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	cmd, opts = newVerifyCommand()
	artifactCmd, args, err = cmd.Find([]string{"artifact", file})
	require.NoError(t, err)
	require.NoError(t, artifactCmd.PreRunE(artifactCmd, args))
	require.Equal(t, file, opts.SubjectFile)
	require.Empty(t, opts.SubjectHash)

	// The artifact flags are local to each command, so the subcommand
	// defines its own and inherits none from verify.
	require.NotNil(t, artifactCmd.Flags().Lookup("subject-hash"))
	require.Nil(t, artifactCmd.InheritedFlags().Lookup("subject-hash"))
}
