// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/carabiner-dev/command/subject"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/spf13/cobra"
)

// newVerifyImageCommand builds "verify image", which resolves a container
// image reference to the digest attestations about the image are bound to.
func newVerifyImageCommand(opts *verifyOptions) *cobra.Command {
	cmd := &cobra.Command{
		Short: "check a container image against a policy",
		Long: fmt.Sprintf(`
%s

ampel verify image checks a container image against a policy. The image is
named by a reference (registry/repository:tag or @digest). A reference with
a tag is resolved at the registry into the digest of the manifest it points
to, which is the digest attestations about the image carry as their subject.
A reference that already carries a digest is used as is, without contacting
the registry. Registry credentials are read from the usual docker config.

For a multi-platform image, the reference resolves to the digest of the
image index, the digest build tools attest to. To check one platform
instead, --platform (for example linux/arm64) selects that platform's
manifest from the index, and its digest becomes the subject.

Attestations attached to the image in its registry are collected by
default, both those cosign stores under the image's .att tag and those
attached as OCI referrers; --registry-attestations=false turns that off.
More evidence is given exactly as for "ampel verify", with --attestation
or --collector.
`, AmpelBanner("Amazing Multipurpose Policy Engine and L")),
		Use: "image REFERENCE",
		Example: `  ampel verify image ghcr.io/example/app:v1.2.3 -p policy.json
  ampel verify image ghcr.io/example/app:v1.2.3 --platform linux/arm64 -p policy.json`,
		SilenceUsage:  false,
		SilenceErrors: false,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("the image reference must be the only argument")
			}
			return nil
		},
		PreRunE: func(_ *cobra.Command, args []string) error {
			opts.SubjectKind = subjectImage
			opts.ImageRef = args[0]
			if opts.RegistryAttestations {
				opts.Collectors = withRegistryCollectors(opts.Collectors, opts.ImageRef)
			}
			return nil
		},
		RunE: runVerify(opts),
	}
	opts.AddFlags(cmd)
	opts.addImageFlags(cmd)
	opts.groupFlags(cmd)
	return cmd
}

// registryCollectorTypes are the collectors that read attestations attached
// to an image in its registry: coci reads the cosign .att tag, oci the OCI
// referrers.
var registryCollectorTypes = []string{"coci", "oci"}

// withRegistryCollectors adds the registry collectors for ref to the
// collector init strings, skipping any the user already configured.
func withRegistryCollectors(collectors []string, ref string) []string {
	for _, t := range registryCollectorTypes {
		init := t + ":" + ref
		if !slices.Contains(collectors, init) {
			collectors = append(collectors, init)
		}
	}
	return collectors
}

// imageSubject resolves an image reference into the resource descriptor
// attestations about the image are bound to: the repository as the name
// and the digest of the manifest (or index) the reference points to. A
// reference carrying a digest is resolved locally; a tag is looked up at
// the registry. When a platform is given, the manifest for that platform
// is selected from the index the reference points to and its digest is
// the subject, which always means contacting the registry.
func imageSubject(ctx context.Context, ref, platform string) (*intoto.ResourceDescriptor, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %q: %w", ref, err)
	}

	var digest string
	switch d, ok := parsed.(name.Digest); {
	case platform != "":
		digest, err = platformDigest(ctx, parsed, platform)
		if err != nil {
			return nil, fmt.Errorf("resolving image reference %q for platform %s: %w", ref, platform, err)
		}
	case ok:
		digest = d.DigestStr()
	default:
		digest, err = crane.Digest(ref, crane.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("resolving image reference %q: %w", ref, err)
		}
	}

	algo, value, err := subject.ParseDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("parsing digest of image %q: %w", ref, err)
	}

	return &intoto.ResourceDescriptor{
		Name:   parsed.Context().Name(),
		Digest: map[string]string{string(algo): value},
	}, nil
}

// platformDigest returns the digest of the manifest for platform behind
// ref. An index must list exactly one manifest satisfying the platform; a
// single image must be built for it.
func platformDigest(ctx context.Context, ref name.Reference, platform string) (string, error) {
	want, err := v1.ParsePlatform(platform)
	if err != nil {
		return "", fmt.Errorf("parsing platform: %w", err)
	}
	desc, err := remote.Get(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}

	if !desc.MediaType.IsIndex() {
		img, err := desc.Image()
		if err != nil {
			return "", err
		}
		cfg, err := img.ConfigFile()
		if err != nil {
			return "", fmt.Errorf("reading image config: %w", err)
		}
		if !cfg.Platform().Satisfies(*want) {
			return "", fmt.Errorf("the image is built for %s, not %s", cfg.Platform(), want)
		}
		return desc.Digest.String(), nil
	}

	idx, err := desc.ImageIndex()
	if err != nil {
		return "", err
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return "", fmt.Errorf("reading image index: %w", err)
	}
	var matches []*v1.Descriptor
	for i := range manifest.Manifests {
		m := &manifest.Manifests[i]
		if m.Platform != nil && m.Platform.Satisfies(*want) {
			matches = append(matches, m)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("the image index has no manifest for %s", want)
	case 1:
		return matches[0].Digest.String(), nil
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Platform.String())
		}
		return "", fmt.Errorf("the image index has several manifests for %s (%v), give a more specific platform", want, names)
	}
}
