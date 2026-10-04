// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"errors"
	"fmt"
	"slices"

	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"

	"github.com/carabiner-dev/ampel/pkg/context"
	"github.com/carabiner-dev/ampel/pkg/evaluator/cel"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

var ResultsAttestationFormats = []string{
	"ampel", // Regular ampel resultSet
	"vsa",   // Verification Summary Attestation
	"svr",   // Simple Verification Result
}

type VerificationOptions struct {
	// Embed the evaluator options
	options.EvaluatorOptions

	// Collectors is a collection of configured attestation fetchers
	Collectors []attestation.Fetcher

	// ContextProviders has a list of providers to read contextual data
	ContextProviders []context.Provider

	// AttestationFiles are additional attestations passed manually
	AttestationFiles []string

	// Attestations are preparsed attestations the policy evaluator receives
	// when called, usually preparsed by the PolicySet evaluator.
	Attestations []attestation.Envelope

	// DefaultEvaluator is the default evaluator we use when a policy does
	// not define one.
	DefaultEvaluator class.Class

	// AttestResults will generate an attestation of the evaluation results
	AttestResults bool

	// AttestFormat specifies the format used when AttestResults is true
	AttestFormat string

	// ResultsAttestationPath stores the path to write the results attestation
	ResultsAttestationPath string

	// SetExitCode sets a non-zero exit code on artifact verification
	SetExitCode bool

	// Policies to evaluate from a PolicySet. Default is to evaluate all.
	Policies []string

	// GitCommitShaHack enables a hack to duplicate gitCommit subjects of read
	// attestations as sha1 when reading attestations
	GitCommitShaHack bool

	// IdentityStrings feeds the signature identities to add to the policy
	// definitions when verifying signatures.
	IdentityStrings []string

	// Keys is a list of public key providers that will be used to verify signed
	// items. These keys will be supplied to verifiers when checking signatures of
	// signed stuff (ie DSSE envelopes). It is up to the policy to recognize any
	// of the matched keys as valid identities.
	//
	// Note that each signature will be verified against all keys loaded, so clients
	// are advised to load only those keys required for each policy evaluation.
	Keys []key.PublicKeyProvider

	// EnforceExpiration forces evaluations to fail when the policy or policy set
	// expiration date has passed. If no expiration date is set, this setting is ignored.
	EnforceExpiration bool

	// AllowEmptySetChains prevents the policy from failing if the chain selectors
	// don't return any mutated subjects.
	AllowEmptySetChains bool

	// LazyBlockEval causes block evaluations to stop as soon as the blocks status
	// is known. This makes evaluation faster but also means that some policies in
	// the block may not be evaluated (and missing from the group's resultSet)
	LazyBlockEval bool

	// ErrOnMissingAttestations causes the verifier to return ErrMissingAttestations
	// (as a Go error wrapped via errors.Join) the moment any tenet cannot be
	// evaluated due to missing attestations. The EvalResult is still populated
	// in Error.Message so callers retain diagnostic detail.
	//
	// The default (false) causes the missing attestations error to surface
	// only as a failed EvalResult, not as a top-level Go error.
	//
	// Intended for programmatic callers that want to detect this condition
	// distinctly from policy violations or signature failures (for example,
	// to drive a wait+retry loop while attestations land).
	ErrOnMissingAttestations bool

	// AdmitUnverified admits attestations that were passed explicitly to the
	// verifier (through Attestations or AttestationFiles) even when they are
	// unsigned or their signature could not be verified, provided the policy
	// pins no signer identities. It exists for callers that hand the verifier
	// evidence on purpose, such as the ampel CLI's --attestation flag, and
	// never applies to attestations fetched by collectors. Admitted
	// unverified attestations reach policies with verification.verified set
	// to false. When the policy (or IdentityStrings) pins signer identities,
	// unverified attestations are always skipped.
	AdmitUnverified bool
}

// Validate checks the options set
func (opts *VerificationOptions) Validate() error {
	errs := []error{}
	if opts.AttestFormat != "" && !slices.Contains(ResultsAttestationFormats, opts.AttestFormat) {
		errs = append(errs, fmt.Errorf("invalid results attestation format: %q", opts.AttestFormat))
	}

	return errors.Join(errs...)
}

var DefaultVerificationOptions = VerificationOptions{
	EvaluatorOptions: options.Default,

	// DefaultEvaluator the the default eval enfine is the lowest version
	// of CEL available
	DefaultEvaluator: cel.Class,

	// ResultsAttestationPath path to the results attestation
	ResultsAttestationPath: "results.intoto.json",

	// Duplicate any gitCommit digests as sha1
	GitCommitShaHack: true,

	// Context providers, by default we enable the envvar provider
	ContextProviders: []context.Provider{},

	// EnforceExpiration is on to check expiration dates by default
	EnforceExpiration: true,

	// AllowEmptySetChains is set to true. This means that if no subjects
	// result from the selectors, the set passes with the policies softfailed.
	AllowEmptySetChains: true,

	// By default, we attesta results in the ampel format
	AttestFormat: "ampel",

	// Don't do LazyBlockEval by default
	LazyBlockEval: false,
}

func NewVerificationOptions() VerificationOptions {
	return DefaultVerificationOptions
}

func (vo *VerificationOptions) WithContextProvider(provider context.Provider) *VerificationOptions {
	vo.ContextProviders = append(vo.ContextProviders, provider)
	return vo
}
