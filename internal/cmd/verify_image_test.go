// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/require"
)

// A reference that carries its digest resolves without touching any
// registry, keeping the digest and naming the subject after the repository.
func TestVerifyImageSubjectDigestRef(t *testing.T) {
	t.Parallel()
	const digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	rd, err := imageSubject(context.Background(), "ghcr.io/example/app@sha256:"+digest)
	require.NoError(t, err)
	require.Equal(t, "ghcr.io/example/app", rd.GetName())
	require.Equal(t, map[string]string{"sha256": digest}, rd.GetDigest())

	// A tag next to the digest is ignored in favor of the digest.
	rd, err = imageSubject(context.Background(), "ghcr.io/example/app:v1@sha256:"+digest)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"sha256": digest}, rd.GetDigest())

	_, err = imageSubject(context.Background(), "ghcr.io/example/app@sha256:nope")
	require.Error(t, err)
	_, err = imageSubject(context.Background(), "not a reference")
	require.Error(t, err)
}

// A tagged reference is resolved at the registry into the digest of the
// manifest the tag points to.
func TestVerifyImageSubjectTagRef(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	img, err := random.Image(256, 1)
	require.NoError(t, err)
	ref := host + "/example/app:v1"
	require.NoError(t, crane.Push(img, ref))
	want, err := img.Digest()
	require.NoError(t, err)

	rd, err := imageSubject(context.Background(), ref)
	require.NoError(t, err)
	require.Equal(t, host+"/example/app", rd.GetName())
	require.Equal(t, map[string]string{"sha256": want.Hex}, rd.GetDigest())

	_, err = imageSubject(context.Background(), host+"/example/app:missing")
	require.ErrorContains(t, err, "resolving image reference")
}

// The image subcommand takes the reference as its only argument, registers
// the registry collectors for it, and the options refuse to run without a
// reference.
func TestVerifyImageArgs(t *testing.T) {
	t.Parallel()
	cmd, opts := newVerifyCommand()
	imageCmd, args, err := cmd.Find([]string{"image", "ghcr.io/example/app:v1"})
	require.NoError(t, err)
	require.Equal(t, "image", imageCmd.Name())
	require.Error(t, imageCmd.Args(imageCmd, nil))
	require.NoError(t, imageCmd.Args(imageCmd, args))
	require.NoError(t, imageCmd.ParseFlags(nil))
	require.NoError(t, imageCmd.PreRunE(imageCmd, args))
	require.Equal(t, subjectImage, opts.SubjectKind)
	require.Equal(t, "ghcr.io/example/app:v1", opts.ImageRef)
	require.Equal(t, []string{"coci:ghcr.io/example/app:v1", "oci:ghcr.io/example/app:v1"}, opts.Collectors)

	// The registry collectors satisfy the evidence requirement on their own.
	opts.PolicyLocation = "policy.json"
	opts.Format = "tty"
	require.NoError(t, opts.Validate())

	opts.ImageRef = ""
	opts.PolicyLocation = "policy.json"
	opts.Format = "tty"
	opts.AttestationFiles = []string{"x"}
	require.ErrorContains(t, opts.Validate(), "no image reference")
}

// The registry collectors are not duplicated when the user configured
// one, and --registry-attestations=false leaves them out.
func TestVerifyImageRegistryCollectors(t *testing.T) {
	t.Parallel()
	const ref = "ghcr.io/example/app:v1"

	cmd, opts := newVerifyCommand()
	imageCmd, args, err := cmd.Find([]string{"image", ref})
	require.NoError(t, err)
	require.NoError(t, imageCmd.ParseFlags([]string{"-c", "oci:" + ref, "-c", "jsonl:att.jsonl"}))
	require.NoError(t, imageCmd.PreRunE(imageCmd, args))
	require.Equal(t, []string{"oci:" + ref, "jsonl:att.jsonl", "coci:" + ref}, opts.Collectors)

	cmd, opts = newVerifyCommand()
	imageCmd, args, err = cmd.Find([]string{"image", ref})
	require.NoError(t, err)
	require.NoError(t, imageCmd.ParseFlags([]string{"--registry-attestations=false"}))
	require.NoError(t, imageCmd.PreRunE(imageCmd, args))
	require.Empty(t, opts.Collectors)
}
