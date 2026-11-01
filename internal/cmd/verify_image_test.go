// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

// A reference that carries its digest resolves without touching any
// registry, keeping the digest and naming the subject after the repository.
func TestVerifyImageSubjectDigestRef(t *testing.T) {
	t.Parallel()
	const digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	rd, err := imageSubject(context.Background(), "ghcr.io/example/app@sha256:"+digest, "")
	require.NoError(t, err)
	require.Equal(t, "ghcr.io/example/app", rd.GetName())
	require.Equal(t, map[string]string{"sha256": digest}, rd.GetDigest())

	// A tag next to the digest is ignored in favor of the digest.
	rd, err = imageSubject(context.Background(), "ghcr.io/example/app:v1@sha256:"+digest, "")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"sha256": digest}, rd.GetDigest())

	_, err = imageSubject(context.Background(), "ghcr.io/example/app@sha256:nope", "")
	require.Error(t, err)
	_, err = imageSubject(context.Background(), "not a reference", "")
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

	rd, err := imageSubject(context.Background(), ref, "")
	require.NoError(t, err)
	require.Equal(t, host+"/example/app", rd.GetName())
	require.Equal(t, map[string]string{"sha256": want.Hex}, rd.GetDigest())

	_, err = imageSubject(context.Background(), host+"/example/app:missing", "")
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

// platformImage builds an image whose config says it is for os/arch.
func platformImage(t *testing.T, os, arch, variant string) v1.Image {
	t.Helper()
	img, err := random.Image(256, 1)
	require.NoError(t, err)
	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	cfg.OS, cfg.Architecture, cfg.Variant = os, arch, variant
	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)
	return img
}

// With --platform the subject is the digest of that platform's manifest in
// the index; an absent or ambiguous platform is an error, and a single
// image is accepted only when built for the platform.
func TestVerifyImageSubjectPlatform(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	amd64 := platformImage(t, "linux", "amd64", "")
	armv7 := platformImage(t, "linux", "arm", "v7")
	armv6 := platformImage(t, "linux", "arm", "v6")
	var idx v1.ImageIndex = empty.Index
	for _, img := range []v1.Image{amd64, armv7, armv6} {
		cfg, err := img.ConfigFile()
		require.NoError(t, err)
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: cfg.Platform()}})
	}
	ref := host + "/example/multi:v1"
	parsed, err := name.ParseReference(ref)
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(parsed, idx))
	indexDigest, err := idx.Digest()
	require.NoError(t, err)
	amd64Digest, err := amd64.Digest()
	require.NoError(t, err)
	armv7Digest, err := armv7.Digest()
	require.NoError(t, err)

	rd, err := imageSubject(context.Background(), ref, "")
	require.NoError(t, err)
	require.Equal(t, indexDigest.Hex, rd.GetDigest()["sha256"])

	rd, err = imageSubject(context.Background(), ref, "linux/amd64")
	require.NoError(t, err)
	require.Equal(t, amd64Digest.Hex, rd.GetDigest()["sha256"])
	require.Equal(t, host+"/example/multi", rd.GetName())

	rd, err = imageSubject(context.Background(), ref, "linux/arm/v7")
	require.NoError(t, err)
	require.Equal(t, armv7Digest.Hex, rd.GetDigest()["sha256"])

	// The digest reference also resolves through the index.
	rd, err = imageSubject(context.Background(), host+"/example/multi@"+indexDigest.String(), "linux/amd64")
	require.NoError(t, err)
	require.Equal(t, amd64Digest.Hex, rd.GetDigest()["sha256"])

	_, err = imageSubject(context.Background(), ref, "linux/arm")
	require.ErrorContains(t, err, "several manifests")
	_, err = imageSubject(context.Background(), ref, "windows/amd64")
	require.ErrorContains(t, err, "no manifest for windows/amd64")
	_, err = imageSubject(context.Background(), ref, "not a platform")
	require.ErrorContains(t, err, "platform")

	// A single image is accepted for its own platform only.
	single := host + "/example/single:v1"
	require.NoError(t, crane.Push(amd64, single))
	rd, err = imageSubject(context.Background(), single, "linux/amd64")
	require.NoError(t, err)
	require.Equal(t, amd64Digest.Hex, rd.GetDigest()["sha256"])
	_, err = imageSubject(context.Background(), single, "linux/arm64")
	require.ErrorContains(t, err, "built for linux/amd64, not linux/arm64")
}
