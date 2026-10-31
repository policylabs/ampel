// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// omsSimpleRootDigest is the root digest of the "simple" model of the
// OpenSSF Model Signing conformance suite, the subject digest recorded in
// the signed bundles published as the spec's test vectors.
const omsSimpleRootDigest = "92745110b1ab4368471cbe31664e10174e954b113a3df333db860317b2c6dec4"

// writeOMSSimpleModel materializes the conformance suite's "simple" model:
// two signed files plus one the signer left out with --ignore-paths.
func writeOMSSimpleModel(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "simple")
	require.NoError(t, os.MkdirAll(root, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "signme-1"), []byte("signme-1\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "signme-2"), []byte("signme-2"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "ignore-me"), nil, 0o600))
	return root
}

// verify model hashes the directory into the OMS root digest, named after
// the directory, so attestations produced by model signing match it.
func TestVerifyModelSubject(t *testing.T) {
	t.Parallel()
	root := writeOMSSimpleModel(t)

	cmd, opts := newVerifyCommand()
	modelCmd, args, err := cmd.Find([]string{"model", root})
	require.NoError(t, err)
	require.NoError(t, modelCmd.ParseFlags([]string{"--ignore-path", "ignore-me"}))
	require.NoError(t, modelCmd.PreRunE(modelCmd, args))
	require.Equal(t, subjectModel, opts.SubjectKind)
	require.Equal(t, root, opts.ModelPath)

	rd, err := opts.SubjectDescriptor()
	require.NoError(t, err)
	require.Equal(t, "simple", rd.GetName())
	require.Equal(t, map[string]string{"sha256": omsSimpleRootDigest}, rd.GetDigest())

	// Without the ignore path the extra file changes the digest.
	opts.ModelIgnorePaths = nil
	rd, err = opts.SubjectDescriptor()
	require.NoError(t, err)
	require.NotEqual(t, omsSimpleRootDigest, rd.GetDigest()["sha256"])
}

// An empty model and a model with a symlink are errors, as the spec
// requires, unless symlinks are explicitly allowed.
func TestVerifyModelSubjectErrors(t *testing.T) {
	t.Parallel()

	_, err := modelSubject(t.TempDir(), nil, false)
	require.ErrorContains(t, err, "no regular files")

	root := writeOMSSimpleModel(t)
	require.NoError(t, os.Symlink("signme-1", filepath.Join(root, "link")))
	_, err = modelSubject(root, []string{"ignore-me"}, false)
	require.ErrorContains(t, err, "symlink")

	rd, err := modelSubject(root, []string{"ignore-me"}, true)
	require.NoError(t, err)
	require.NotEqual(t, omsSimpleRootDigest, rd.GetDigest()["sha256"])
}

// The model command needs exactly one argument, and the options refuse to
// run without a model path.
func TestVerifyModelArgs(t *testing.T) {
	t.Parallel()
	cmd, opts := newVerifyCommand()
	modelCmd, _, err := cmd.Find([]string{"model"})
	require.NoError(t, err)
	require.Error(t, modelCmd.Args(modelCmd, nil))
	require.Error(t, modelCmd.Args(modelCmd, []string{"a", "b"}))
	require.NoError(t, modelCmd.Args(modelCmd, []string{"a"}))

	opts.SubjectKind = subjectModel
	opts.PolicyLocation = "policy.json"
	opts.Format = "tty"
	opts.AttestationFiles = []string{"x"}
	require.ErrorContains(t, opts.Validate(), "no model path")
}
