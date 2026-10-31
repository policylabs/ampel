// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/carabiner-dev/command/subject"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
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
image index, the digest build tools attest to. To check a single platform
give the digest of that platform's manifest instead.

The policy and the evidence are given exactly as for "ampel verify".
`, AmpelBanner("Amazing Multipurpose Policy Engine and L")),
		Use:           "image REFERENCE",
		Example:       "  ampel verify image ghcr.io/example/app:v1.2.3 -p policy.json -c coci:ghcr.io/example/app:v1.2.3",
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
			return nil
		},
		RunE: runVerify(opts),
	}
	opts.AddFlags(cmd)
	opts.groupFlags(cmd)
	return cmd
}

// imageSubject resolves an image reference into the resource descriptor
// attestations about the image are bound to: the repository as the name
// and the digest of the manifest (or index) the reference points to. A
// reference carrying a digest is resolved locally; a tag is looked up at
// the registry.
func imageSubject(ctx context.Context, ref string) (*intoto.ResourceDescriptor, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %q: %w", ref, err)
	}

	var digest string
	if d, ok := parsed.(name.Digest); ok {
		digest = d.DigestStr()
	} else {
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
