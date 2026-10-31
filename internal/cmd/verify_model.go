// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/carabiner-dev/command/subject"
	"github.com/carabiner-dev/model-signing/pkg/serializer/dir"
	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
	"github.com/fatih/color"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/spf13/cobra"
)

// newVerifyModelCommand builds "verify model", which hashes an AI model
// directory the way OpenSSF Model Signing does and verifies the result.
func newVerifyModelCommand(opts *verifyOptions) *cobra.Command {
	cmd := &cobra.Command{
		Short: "check an AI model directory against a policy",
		Long: fmt.Sprintf(`
%s

ampel verify model checks an AI model against a policy. The model is a
directory (or a single file) whose contents are hashed the way the OpenSSF
Model Signing (OMS) specification defines: every regular file under the
model root is hashed and the digests, in path order, are hashed again into
the root digest that OMS signatures record as their subject. Attestations
about the model, such as its model signing bundle, match that digest.

Git metadata at the model root (.git, .gitignore, .gitattributes, .github)
is never part of the digest. Other files, such as a signature bundle kept
next to the model weights, are left out with --ignore-path. Symlinks are an
error unless --allow-symlinks is set, in which case links to files are
hashed through their targets, as a signer with the same setting would.

The policy and the evidence are given exactly as for "ampel verify".
`, AmpelBanner("Amazing Multipurpose Policy Engine and L")),
		Use:           "model PATH",
		Example:       "  ampel verify model ./my-model -p policy.json -a attestation.intoto.json --ignore-path ignored.txt",
		SilenceUsage:  false,
		SilenceErrors: false,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("the path to the model directory must be the only argument")
			}
			return nil
		},
		PreRunE: func(_ *cobra.Command, args []string) error {
			opts.SubjectKind = subjectModel
			opts.ModelPath = args[0]
			return nil
		},
		RunE: runVerify(opts),
	}
	opts.AddFlags(cmd)
	opts.addModelFlags(cmd)
	opts.groupFlags(cmd)
	return cmd
}

// modelSubject hashes the model at path into the resource descriptor OMS
// signatures use as their subject: the model's basename and its sha256
// root digest.
func modelSubject(path string, ignorePaths []string, allowSymlinks bool) (*intoto.ResourceDescriptor, error) {
	o := options.Default()
	o.IgnorePaths = ignorePaths
	o.AllowSymlinks = allowSymlinks

	digest, err := dir.ComputeDigest(path, o)
	if err != nil {
		return nil, fmt.Errorf("hashing model %s: %w", color.New(color.FgHiWhite).Sprint(path), err)
	}

	algo, value, err := subject.ParseDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("parsing model digest %q: %w", digest, err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving model path: %w", err)
	}

	return &intoto.ResourceDescriptor{
		Name:   filepath.Base(abs),
		Digest: map[string]string{string(algo): value},
	}, nil
}
