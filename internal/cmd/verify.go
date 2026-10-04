// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	keyOpts "github.com/carabiner-dev/command/keys"
	"github.com/carabiner-dev/hasher"
	"github.com/fatih/color"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector"
	"github.com/policylabs/policy"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/policy/options"
	"github.com/policylabs/signer"
	"github.com/policylabs/signer/key"
	signerOpts "github.com/policylabs/signer/options"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/helpers"

	"github.com/carabiner-dev/ampel/internal/render"
	"github.com/carabiner-dev/ampel/pkg/attest"
	acontext "github.com/carabiner-dev/ampel/pkg/context"
	"github.com/carabiner-dev/ampel/pkg/verifier"
)

var (
	hashRegexStr = `^(\bsha1\b|\bsha256\b|\bsha512\b|\bsha3\b|\bgitCommit\b):([a-f0-9]+)$`
	hashRegex    *regexp.Regexp
)

// attestFormatFor maps a --format value to its canonical attester
// format name. Returns ok=false for non-attestation display formats
// (tty, html, markdown), which should still be rendered through the
// render engine. The "attestation" alias maps to "ampel" so the
// stdout output of --format=attestation matches what
// --attest-format=ampel produces.
func attestFormatFor(format string) (string, bool) {
	switch format {
	case "attestation":
		return "ampel", true
	case formatVSA:
		return formatVSA, true
	case formatSVR:
		return formatSVR, true
	default:
		return "", false
	}
}

const (
	formatVSA = "vsa"
	formatSVR = "svr"
)

const (
	grpSubject      = "subject"
	grpPolicy       = "policy"
	grpEvidence     = "evidence"
	grpContext      = "context"
	grpResults      = "results"
	grpSigning      = "signing"
	grpVerification = "verification"
)

// verifyFlagGroups defines the order and headings of the flag sections
// rendered by `ampel verify --help`. Empty groups are skipped, so the
// signing section won't appear until signer flags are wired in.
var verifyFlagGroups = []flagGroup{
	{ID: grpSubject, Title: "Subject Specification:"},
	{ID: grpPolicy, Title: "Policy Options & Specification:"},
	{ID: grpEvidence, Title: "Evidence Collection:"},
	{ID: grpContext, Title: "Context Definition:"},
	{ID: grpResults, Title: "Results Attestation & Output:"},
	{ID: grpSigning, Title: "Signing Flags:"},
	{ID: grpVerification, Title: "Verification Flags:"},
}

type verifyOptions struct {
	// FailSkip makes the command exit non-zero when the evaluation result
	// is SKIP, that is, when no policy applied to the subject.
	FailSkip bool

	verifier.VerificationOptions
	keyOpts.Options
	PolicyLocation        string
	Format                string
	PolicyOutput          bool
	ContextEnv            bool
	ContextJSON           string
	ContextYAML           string
	ContextStringVals     []string
	Collectors            []string
	Publishers            []string
	Subject               string
	SubjectFile           string
	SubjectHash           string
	PolicyIdentityStrings []string
	PolicyVerify          bool
	PolicyKeyPaths        []string
	Sign                  bool
	SignerSet             *signerOpts.SignerSet
}

// AddFlags adds the flags
func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	o.Options.AddFlags(cmd)
	cmd.PersistentFlags().StringVarP(
		&o.Subject, "subject", "s", "", "subject hash (algo:value) or path to file (alternative to positional argument)",
	)

	cmd.PersistentFlags().StringVar(
		&o.SubjectFile, "subject-file", "", "file to verify",
	)

	cmd.PersistentFlags().StringVar(
		&o.SubjectHash, "subject-hash", "", "hash to verify",
	)

	cmd.PersistentFlags().StringVarP(
		&o.PolicyLocation, "policy", "p", "", "policy/policySet (h)json source location (file path, URL, or VCS locator)",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&o.AttestationFiles, "attestation", "a", o.AttestationFiles, "additional attestations to read (admitted unsigned)",
	)

	cmd.PersistentFlags().BoolVar(
		&o.AttestResults, "attest-results", o.AttestResults, "write an attestation with the evaluation results to --results-path",
	)

	cmd.PersistentFlags().StringVar(
		&o.AttestFormat, "attest-format", verifier.DefaultVerificationOptions.AttestFormat, fmt.Sprintf("format used when attest-results is true %v", verifier.ResultsAttestationFormats),
	)

	cmd.PersistentFlags().StringSliceVarP(
		&o.ContextStringVals, "context", "x", []string{}, "evaluation context value definitions",
	)

	cmd.PersistentFlags().StringVar(
		&o.ContextJSON, "context-json", "", "JSON struct with the context definition or prefix with @ to read from a file",
	)

	cmd.PersistentFlags().StringVar(
		&o.ContextYAML, "context-yaml", "", "YAML struct with the context definition or prefix with @ to read from a file",
	)

	cmd.PersistentFlags().BoolVar(
		&o.ContextEnv, "context-env", true, "Support reading context values from env vars",
	)

	cmd.PersistentFlags().StringVar(
		&o.ResultsAttestationPath, "results-path", o.ResultsAttestationPath, "path to the evaluation results attestation",
	)

	cmd.PersistentFlags().StringVarP(
		&o.Format, "format", "f", "tty", fmt.Sprintf("output format %v", render.Formats()),
	)

	cmd.PersistentFlags().StringSliceVarP(
		&o.Collectors, "collector", "c", []string{}, "attestation collectors to initialize",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.Publishers, "publish", []string{}, "publishers to emit evaluation results to, as \"driver:spec\"",
	)

	cmd.PersistentFlags().BoolVar(
		&o.SetExitCode, "exit-code", true, "set a non-zero exit code on policy verification fail",
	)

	cmd.PersistentFlags().BoolVar(
		&o.FailSkip, "fail-skip", false, "also set a non-zero exit code when the result is SKIP (no policy applied to the subject)",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.Policies, "pid", []string{}, "list of policy IDs to evaluate from a set (defaults to all)",
	)

	cmd.PersistentFlags().BoolVar(
		&o.PolicyOutput, "policy-out", false, "render the eval results per policy, more detailed than the set view",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.IdentityStrings, "signer", []string{}, "list of signer identities to verify attestations",
	)

	cmd.PersistentFlags().BoolVar(
		&o.EnforceExpiration, "expiration", verifier.DefaultVerificationOptions.EnforceExpiration, "enforce policy expiration dates",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.PolicyIdentityStrings, "policy-signer", []string{}, "signer identities to verify signed policies",
	)

	cmd.PersistentFlags().BoolVar(
		&o.PolicyVerify, "policy-verify", true, "verify policy signatures",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.PolicyKeyPaths, "policy-key", []string{}, "path to public keys to verify policies",
	)

	cmd.PersistentFlags().Int8Var(
		&o.ParallelWorkers, "workers", verifier.DefaultVerificationOptions.ParallelWorkers, "number of evaluation threads to run in parallel",
	)

	cmd.PersistentFlags().BoolVar(
		&o.AllowEmptySetChains, "allow-empty-set-chain", verifier.DefaultVerificationOptions.AllowEmptySetChains, "don't fail PolicySets when chains are empty",
	)

	cmd.PersistentFlags().BoolVar(
		&o.SkipUnsupportedRuntime, "skip-unsupported-runtime", verifier.DefaultVerificationOptions.SkipUnsupportedRuntime, "soft-fail policies when the runtime or plugins are unavailable",
	)

	cmd.PersistentFlags().BoolVar(
		&o.Sign, "sign", false, "sign the results attestation",
	)
	o.SignerSet.AddFlags(cmd)

	groupFlags(cmd, grpSubject, "subject", "subject-file", "subject-hash")
	groupFlags(cmd, grpPolicy, "policy", "pid", "policy-out", "policy-verify", "policy-key", "policy-signer", "expiration")
	groupFlags(cmd, grpEvidence, "key", "attestation", "collector", "signer")
	groupFlags(cmd, grpContext, "context", "context-json", "context-yaml", "context-env")
	groupFlags(cmd, grpResults, "attest-results", "attest-format", "results-path", "format", "publish")
	groupFlags(cmd, grpVerification, "exit-code", "fail-skip", "workers", "allow-empty-set-chain", "skip-unsupported-runtime")
	groupFlags(cmd, grpSigning, "sign")
	// Sweep every flag the SignerSet just registered into the
	// Signing section. Doing it post-hoc keeps the signer library's
	// AddFlags surface untouched.
	groupFlagsByPrefix(cmd, grpSigning, "signing-", "sigstore-", "spiffe-")

	registerFlagGroups(cmd, verifyFlagGroups...)
	applyFlagGroupTemplate(cmd)
}

func parseHash(estring string) (algo, value string, err error) {
	if hashRegex == nil {
		hashRegex = regexp.MustCompile(hashRegexStr)
	}

	// If the string matches algo:hexValue then we never try to look
	// for a file. Never.
	pts := hashRegex.FindStringSubmatch(estring)
	if pts != nil {
		algo := strings.ToLower(pts[1])
		if _, ok := intoto.HashAlgorithms[algo]; !ok {
			return "", "", errors.New("invalid hash algorithm in subject")
		}
		return algo, pts[2], nil
	}
	return "", "", fmt.Errorf("error parsing hash string")
}

// SubjectDescriptor parses the subject string read from the command line
// and returns a resource descriptor, either by synhesizing it from the specified
// hash or by hashing a file.
func (o *verifyOptions) SubjectDescriptor() (attestation.Subject, error) {
	// If we have a hash, check it and create the descriptor:
	if o.SubjectHash != "" {
		algo, val, err := parseHash(o.SubjectHash)
		if err != nil {
			return nil, err
		}

		return &intoto.ResourceDescriptor{
			Digest: map[string]string{algo: val},
		}, nil
	}

	hashes, err := hasher.New().HashFiles([]string{o.SubjectFile})
	if err != nil {
		return nil, fmt.Errorf("hashing subject file: %w", err)
	}
	return hashes.ToResourceDescriptors()[0], nil
}

// LoadPublicKeys parses the public keys and loads them into the verification
// options set.
func (o *verifyOptions) LoadPublicKeys() error {
	keys, err := o.ParseKeys()
	if err != nil {
		return err
	}
	o.Keys = keys
	return nil
}

func (o *verifyOptions) Validate() error {
	errs := []error{
		o.VerificationOptions.Validate(),
	}
	if o.SubjectFile == "" && o.SubjectHash == "" {
		errs = append(errs, fmt.Errorf("no subject specified (use --subject, --subject-file or --subject-hash)"))
	}

	if o.SubjectFile != "" && o.SubjectHash != "" {
		errs = append(errs, fmt.Errorf("subject specified twice (as file and hash)"))
	}

	if o.PolicyLocation == "" {
		errs = append(errs, errors.New("a policy file must be defined"))
	}

	if o.Format == "" {
		errs = append(errs, errors.New("no output format defined"))
	} else if !slices.Contains(render.Formats(), o.Format) {
		errs = append(errs, fmt.Errorf("invalid format %q (must be one of %v)", o.Format, render.Formats()))
	}

	if o.ParallelWorkers <= 0 {
		errs = append(errs, errors.New("parallel workers must be larger than 0"))
	}

	if len(o.AttestationFiles) == 0 && len(o.Collectors) == 0 {
		errs = append(errs, errors.New("no attestation sources specified (collectors or files)"))
	}

	if o.Sign {
		_, stdoutIsAttest := attestFormatFor(o.Format)
		if !o.AttestResults && !stdoutIsAttest {
			errs = append(errs, errors.New("--sign requires --attest-results or --format=attestation|vsa|svr (nothing to sign otherwise)"))
		}
		if err := o.SignerSet.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("validating signer config: %w", err))
		}
	}

	return errors.Join(errs...)
}

func addVerify(parentCmd *cobra.Command) {
	opts := verifyOptions{
		VerificationOptions: verifier.NewVerificationOptions(),
		SignerSet:           signerOpts.DefaultSignerSet(),
	}
	// Attestations passed with --attestation are evidence the user chose to
	// hand the verifier, so they are admitted even when unsigned or signed
	// with a key we do not hold (unless the policy pins signer identities).
	//
	// Evidence fetched by collectors never gets this treatment.
	opts.AdmitUnverified = true
	evalCmd := &cobra.Command{
		Short: "check artifacts against a policy",
		Long: fmt.Sprintf(`
%s

Ampel verify checks an artifact (a subject) against a policy file to assert
the policy tenets to be true.

To verify an artifact, ampel required three pieces:

%s
This is often an artifact such as a file. Most commonly, a policy will be evaluated
against a hash. AMPEL can compute the hashes from files for you (--subject-file)
or you can specify a hash in the command line using --subject-hash.

%s
The policy code. Ampel policies are written in JSON, they can be signed and verified 
just as any other attestation. The policy contains Tenets, the principles that
we want to be true to verify an artifact. Tenets are written in a language such
as CEL and once verified are turned into Assertions once verified using available 
evidence.

%s
Evidence lets Ampel prove that the policy Tenets are true. Ampel is designed to
operate on signed attestations which capture evidence in an envelope that makes
it immutable, verifiable and linked to an identity to ensure the highest levels
of trust. Attestations can be supplied through the command line or can be obtained
using a collector.

		`,
			AmpelBanner("Amazing Multipurpose Policy Engine and L"),
			color.New(color.FgHiWhite).Sprint("The Subject"),
			color.New(color.FgHiWhite).Sprint("The Policy"),
			color.New(color.FgHiWhite).Sprint("Attested Evidence"),
		),
		Use:               "verify [subject]",
		SilenceUsage:      false,
		SilenceErrors:     false,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if opts.Subject == "" {
					opts.Subject = args[0]
				} else if opts.Subject != args[0] {
					return fmt.Errorf("subject specified twice: got %q from positional argument and %q from -s flag (use only one)", args[0], opts.Subject)
				}
			}

			if opts.Subject != "" {
				// Always check the hash first to avoid fooling the hash with a
				// carfule placed file
				if _, _, err := parseHash(opts.Subject); err == nil {
					if opts.SubjectHash == "" {
						opts.SubjectHash = opts.Subject
					} else if opts.SubjectHash != opts.Subject {
						return fmt.Errorf("subject hash specified twice")
					}
				} else if helpers.Exists(opts.Subject) {
					if opts.SubjectFile == "" {
						opts.SubjectFile = opts.Subject
					} else {
						return fmt.Errorf("subject file specified twice")
					}
				} else {
					return fmt.Errorf("unable to identify subject string %q", opts.Subject)
				}
			}

			return nil
		},
		RunE: func(c *cobra.Command, _ []string) error {
			c.SilenceUsage = true
			return opts.Run()
		},
	}

	opts.AddFlags(evalCmd)
	parentCmd.AddCommand(evalCmd)
}

// Run executes the verify command logic.
func (opts *verifyOptions) Run() error {
	// Validate options
	if err := opts.Validate(); err != nil {
		return err
	}

	// Read the subject from the specified string:
	subject, err := opts.SubjectDescriptor()
	if err != nil {
		return fmt.Errorf("resolving subject string: %w", err)
	}

	// Parse any keys for the policy check
	keys, err := parsePolicyKeys(opts)
	if err != nil {
		return err
	}

	// Set up the collector and verifier early so we can pre-fetch
	// attestations concurrently with policy compilation.
	if err := collector.LoadDefaultRepositoryTypes(); err != nil {
		return fmt.Errorf("loading repository collector types: %w", err)
	}

	if err := opts.LoadPublicKeys(); err != nil {
		return fmt.Errorf("loading keys: %w", err)
	}

	ampel, err := verifier.New(
		verifier.WithCollectorInits(opts.Collectors),
		verifier.WithPublisherInits(opts.Publishers),
		verifier.WithKeys(opts.Keys...),
	)
	if err != nil {
		return fmt.Errorf("creating verifier: %w", err)
	}

	// Build the context providers as specified in the options
	if err := opts.buildContextProviders(); err != nil {
		return fmt.Errorf("building context providers: %w", err)
	}

	// Run policy compilation and attestation pre-fetch concurrently.
	// Policy compilation (git clone for remote policies) and collector
	// fetching (OCI registry I/O) are independent and expensive.
	var (
		compileSet *papi.PolicySet
		compilePcy *papi.Policy
		compileGrp *papi.PolicyGroup
		compileVer attestation.Verification
		compileErr error
		wg         sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		compileSet, compilePcy, compileGrp, compileVer, compileErr = policy.NewCompiler().CompileVerifyLocation(
			opts.PolicyLocation,
			options.WithIdentityString(opts.PolicyIdentityStrings...),
			options.WithPublicKey(keys...),
			options.WithVerifySignatures(opts.PolicyVerify),
		)
	}()

	// Pre-fetch attestations into the collector's cache so that the
	// Verify call below gets an immediate cache hit.
	wg.Add(1)
	go func() {
		defer wg.Done()
		//nolint:errcheck,gosec // Best-effort cache warming; Verify will re-fetch on miss.
		ampel.Collector.FetchAttestationsBySubject(
			context.Background(), []attestation.Subject{subject},
		)
	}()

	wg.Wait()

	if compileErr != nil {
		return fmt.Errorf("compiling policy: %w", compileErr)
	}

	if opts.PolicyVerify && compileVer != nil {
		if !compileVer.GetVerified() {
			//nolint:errcheck,forcetypeassert
			return fmt.Errorf("policy signature verification failed: %w", compileVer.(error))
		}
	}

	// Run the evaluation (attestations should already be cached):
	results, err := ampel.Verify(context.Background(), &opts.VerificationOptions, policy.PolicyOrSetOrGroup(compileSet, compilePcy, compileGrp), subject)
	if err != nil {
		return fmt.Errorf("running subject verification: %w", err)
	}

	stdoutAttestFmt, stdoutIsAttest := attestFormatFor(opts.Format)

	// Build the attester once. The signer (when --sign is set)
	// applies to both the file output (--attest-results) and the
	// stdout attestation output (--format=attestation|vsa|svr).
	var attesterOpts []attest.FnOpt
	if opts.Sign {
		s, err := signer.NewSignerFromSet(opts.SignerSet)
		if err != nil {
			return fmt.Errorf("building signer: %w", err)
		}
		attesterOpts = append(attesterOpts, attest.WithSigner(s))
	}
	attester := attest.New(attesterOpts...)

	if opts.AttestResults {
		if err := attester.AttestToFile(
			opts.ResultsAttestationPath, results,
			attest.WithFormat(opts.AttestFormat),
		); err != nil {
			return fmt.Errorf("attesting results: %w", err)
		}
	}

	if stdoutIsAttest {
		if err := attester.AttestTo(
			os.Stdout, results, attest.WithFormat(stdoutAttestFmt),
		); err != nil {
			return fmt.Errorf("rendering attestation to stdout: %w", err)
		}
		if opts.exitNonZero(results.GetStatus()) {
			os.Exit(1)
		}
		return nil
	}

	eng := render.NewEngine()
	if err := eng.SetDriver(opts.Format); err != nil {
		return err
	}

	switch r := results.(type) {
	case *papi.Result:
		if err := eng.RenderResult(os.Stdout, r); err != nil {
			return fmt.Errorf("rendering result: %w", err)
		}
	case *papi.ResultGroup:
		if err := eng.Driver.RenderResultGroup(os.Stdout, r); err != nil {
			return fmt.Errorf("rendering result: %w", err)
		}
	case *papi.ResultSet:
		if opts.PolicyOutput || len(opts.Policies) > 0 {
			for _, r := range r.GetResults() {
				if err := eng.RenderResult(os.Stdout, r); err != nil {
					return fmt.Errorf("rendering results: %w", err)
				}
			}
			for _, g := range r.GetGroups() {
				if err := eng.Driver.RenderResultGroup(os.Stdout, g); err != nil {
					return fmt.Errorf("rendering group results: %w", err)
				}
			}
		} else if err := eng.RenderResultSet(os.Stdout, r); err != nil {
			return fmt.Errorf("rendering results: %w", err)
		}
	}

	if opts.exitNonZero(results.GetStatus()) {
		os.Exit(1)
	}

	return nil
}

// buildContextProviders initializes the context providers defined in the
// options set.
func (opts *verifyOptions) buildContextProviders() (err error) {
	// Pass the -x flags as a new StringMapList list provider
	if len(opts.ContextStringVals) > 0 {
		l, err := acontext.NewStringMapList(opts.ContextStringVals)
		if err != nil {
			return err
		}
		opts.WithContextProvider(l)
	}

	// Read the evaluation context data from JSON:
	if opts.ContextJSON != "" {
		var provider acontext.Provider
		// If the JSON file starts with an @, then we read from a file (curl style)
		path, ok := strings.CutPrefix(opts.ContextJSON, "@")
		if ok {
			provider, err = acontext.NewProviderFromJSONFile(path)
			if err != nil {
				return fmt.Errorf("processing JSON context file: %w", err)
			}
		} else {
			provider, err = acontext.NewProviderFromJSON(strings.NewReader(opts.ContextJSON))
			if err != nil {
				return fmt.Errorf("processing JSON context: %w", err)
			}
		}
		opts.WithContextProvider(provider)
	}

	// Read the evaluation context data from YAML:
	if opts.ContextYAML != "" {
		var provider acontext.Provider
		// If the YAML file starts with an @, then we read from a file (curl style)
		path, ok := strings.CutPrefix(opts.ContextYAML, "@")
		if ok {
			provider, err = acontext.NewProviderFromYAMLFile(path)
			if err != nil {
				return fmt.Errorf("processing YAML context file: %w", err)
			}
		} else {
			provider, err = acontext.NewProviderFromYAML(strings.NewReader(opts.ContextYAML))
			if err != nil {
				return fmt.Errorf("processing YAML context: %w", err)
			}
		}
		opts.WithContextProvider(provider)
	}

	// Load the environment context reader if selected
	if opts.ContextEnv {
		opts.WithContextProvider(acontext.NewEnvContextReader())
	}
	return nil
}

// parsePolicyKeys parses the policy public keus
func parsePolicyKeys(opt *verifyOptions) ([]key.PublicKeyProvider, error) {
	parser := key.NewParser()
	ret := []key.PublicKeyProvider{}
	for _, path := range opt.PolicyKeyPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading policy key file: %w", err)
		}
		k, err := parser.ParsePublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}
		ret = append(ret, k)
	}
	return ret, nil
}

// exitNonZero reports if the command must exit with a non-zero code for the
// given evaluation status. --exit-code=false disables result-based exit
// codes altogether; with it on, FAIL always exits non-zero and SKIP does
// too when --fail-skip treats "no policy applied" as a failure.
func (opts *verifyOptions) exitNonZero(status string) bool {
	if !opts.SetExitCode {
		return false
	}
	switch status {
	case papi.StatusFAIL:
		return true
	case papi.StatusSKIP:
		return opts.FailSkip
	default:
		return false
	}
}
