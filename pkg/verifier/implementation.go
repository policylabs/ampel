// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/collector/envelope"
	"github.com/carabiner-dev/collector/envelope/bare"
	"github.com/carabiner-dev/collector/filters"
	"github.com/carabiner-dev/collector/statement/intoto"
	papi "github.com/carabiner-dev/policy/api/v1"
	sapi "github.com/carabiner-dev/signer/api/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	acontext "github.com/carabiner-dev/ampel/pkg/context"
	"github.com/carabiner-dev/ampel/pkg/evaluator"
	"github.com/carabiner-dev/ampel/pkg/evaluator/cel"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/evalcontext"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
	"github.com/carabiner-dev/ampel/pkg/transformer"
)

var defaultEvaluatorClass = class.MustParseClass("default")

// AmpelImplementation
type AmpelVerifier interface {
	// CheckPolicy verifies the policy is sound to evaluate before running it
	CheckPolicy(context.Context, *VerificationOptions, *papi.Policy) error
	CheckPolicySet(context.Context, *VerificationOptions, *papi.PolicySet) error
	CheckPolicyGroup(context.Context, *VerificationOptions, *papi.PolicyGroup) error
	GatherAttestations(context.Context, *VerificationOptions, *collector.Agent, *papi.Policy, attestation.Subject, []attestation.Envelope) ([]attestation.Envelope, error)
	ParseAttestations(context.Context, *VerificationOptions, attestation.Subject) ([]attestation.Envelope, error)
	BuildEvaluators(*VerificationOptions, *papi.Policy) (map[class.Class]evaluator.Evaluator, error)
	BuildGroupEvaluators(*VerificationOptions, *papi.PolicyGroup) (map[class.Class]evaluator.Evaluator, error)
	BuildTransformers(*VerificationOptions, *papi.Policy) (map[transformer.Class]transformer.Transformer, error)
	Transform(*VerificationOptions, map[transformer.Class]transformer.Transformer, *papi.Policy, attestation.Subject, []attestation.Predicate) (attestation.Subject, []attestation.Predicate, error)

	// CheckIdentities verifies that attestations are signed by the policy identities
	CheckIdentities(context.Context, *VerificationOptions, []*sapi.Identity, []attestation.Envelope) (bool, []admission, []error, error)

	FilterAttestations(*VerificationOptions, attestation.Subject, []attestation.Envelope, []admission) ([]attestation.Predicate, error)
	AssertResult(*papi.Policy, *papi.Result) error

	// VerifySubject runs the verification process.
	VerifySubject(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *papi.Policy, map[string]any, attestation.Subject, []attestation.Predicate) (*papi.Result, error)

	// ProcessChainedSubjects proceses the chain of attestations to find the ultimate
	// subject a policy is supposed to operate on
	ProcessChainedSubjects(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *collector.Agent, papi.ChainProvider, map[string]any, attestation.Subject, []attestation.Envelope) (attestation.Subject, []*papi.ChainedSubject, bool, error)

	// ProcessPolicySetChainedSubjects executesd a PolicySet's ChainLink and returns
	// the resulting list of subjects from the evaluator.
	ProcessPolicySetChainedSubjects(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, *collector.Agent, *papi.PolicySet, map[string]any, attestation.Subject, []attestation.Envelope) ([]attestation.Subject, []*papi.ChainedSubject, bool, error)

	// AssembleEvalContextValues builds the policy context values by mixing defaults and defined values
	AssembleEvalContextValues(context.Context, *VerificationOptions, map[class.Class]evaluator.Evaluator, map[string]*papi.ContextVal) (map[string]any, error)
}

type defaultIplementation struct{}

// normalizeSubjectDigests applies gitCommit<->sha1 normalization to ensure
// that subjects specified with sha1: prefix match attestations using gitCommit:
// digest type and vice versa. This enables evidence chain matching for git
// commits regardless of which digest type identifier is used.
//
// The function creates a copy of the subject with normalized digests when
// normalization is enabled, leaving the original subject unchanged otherwise.
func normalizeSubjectDigests(subject attestation.Subject, enableHack bool) attestation.Subject {
	if !enableHack {
		return subject
	}

	origDigest := subject.GetDigest()
	_, hasCommit := origDigest[string(gointoto.AlgorithmGitCommit)]
	_, hasSHA1 := origDigest[string(gointoto.AlgorithmSHA1)]

	// Only apply normalization if we have one but not the other and it looks like
	// a git commit SHA (40 hex characters)
	needsNormalization := false
	if hasCommit && !hasSHA1 && len(origDigest[string(gointoto.AlgorithmGitCommit)]) == 40 {
		needsNormalization = true
	} else if hasSHA1 && !hasCommit && len(origDigest[string(gointoto.AlgorithmSHA1)]) == 40 {
		needsNormalization = true
	}

	if !needsNormalization {
		return subject
	}

	// Clone the digest map to avoid concurrent map writes when multiple
	// goroutines normalize the same subject simultaneously
	digest := maps.Clone(origDigest)

	// Now apply normalization to the cloned map
	if hasCommit && !hasSHA1 {
		digest[string(gointoto.AlgorithmSHA1)] = digest[string(gointoto.AlgorithmGitCommit)]
	} else if hasSHA1 && !hasCommit {
		digest[string(gointoto.AlgorithmGitCommit)] = digest[string(gointoto.AlgorithmSHA1)]
	}

	// Clone the subject with the normalized digests
	return &gointoto.ResourceDescriptor{
		Name:   subject.GetName(),
		Uri:    subject.GetUri(),
		Digest: digest,
	}
}

// CheckPolicy verifies the policy before evaluation to ensure it is fit to run.
func (di *defaultIplementation) CheckPolicy(ctx context.Context, opts *VerificationOptions, p *papi.Policy) error {
	if opts == nil {
		return errors.New("verifier options are not set")
	}
	if p.GetMeta() != nil &&
		p.GetMeta().GetExpiration() != nil &&
		p.GetMeta().GetExpiration().AsTime().Before(time.Now()) &&
		opts.EnforceExpiration {
		return PolicyError{
			error: errors.New("the policy has expired"), // TODO(puerco): Const error
			Guidance: fmt.Sprintf(
				"The policy expired on %s, update the policy source",
				p.GetMeta().GetExpiration().AsTime().Format(time.UnixDate),
			),
		}
	}

	// Extract public keys from policy identities and add them to the
	// verification options so they are available for attestation verification.
	for _, id := range p.GetIdentities() {
		if id.GetKey() == nil {
			continue
		}
		pk, err := id.PublicKey()
		if err != nil {
			return fmt.Errorf("parsing public key from policy identity %q: %w", id.GetId(), err)
		}
		if pk != nil {
			opts.Keys = append(opts.Keys, pk)
		}
	}

	return nil
}

// CheckPolicySet verifies the policySet before evaluating its policies to ensure
// it is fit to run.
func (di *defaultIplementation) CheckPolicySet(ctx context.Context, opts *VerificationOptions, set *papi.PolicySet) error {
	if opts == nil {
		return errors.New("verifier options are not set")
	}
	if set.GetMeta() != nil &&
		set.GetMeta().GetExpiration() != nil &&
		set.GetMeta().GetExpiration().AsTime().Before(time.Now()) &&
		opts.EnforceExpiration {
		return PolicyError{
			error: errors.New("the policy has expired"), // TODO(puerco): Const error
			Guidance: fmt.Sprintf(
				"The policySet expired on %s, update the policy source",
				set.GetMeta().GetExpiration().AsTime().Format(time.UnixDate),
			),
		}
	}

	// Extract public keys from common identities so they are available
	// for attestation signature verification during collection.
	for _, id := range set.GetCommon().GetIdentities() {
		if id.GetKey() == nil {
			continue
		}
		pk, err := id.PublicKey()
		if err != nil {
			return fmt.Errorf("parsing public key from policy identity %q: %w", id.GetId(), err)
		}
		if pk != nil {
			opts.Keys = append(opts.Keys, pk)
		}
	}

	return nil
}

// CheckPolicySet verifies the policySet before evaluating its policies to ensure
// it is fit to run.
func (di *defaultIplementation) CheckPolicyGroup(ctx context.Context, opts *VerificationOptions, grp *papi.PolicyGroup) error {
	if opts == nil {
		return errors.New("verifier options are not set")
	}
	if err := grp.Validate(); err != nil {
		return PolicyError{
			error:    err,
			Guidance: "PolicyGroup failed validation",
		}
	}
	if grp.GetMeta() != nil &&
		grp.GetMeta().GetExpiration() != nil &&
		grp.GetMeta().GetExpiration().AsTime().Before(time.Now()) &&
		opts.EnforceExpiration {
		return PolicyError{
			error: errors.New("the policy has expired"), // TODO(puerco): Const error
			Guidance: fmt.Sprintf(
				"The policyGroup expired on %s, update the policy source",
				grp.GetMeta().GetExpiration().AsTime().Format(time.UnixDate),
			),
		}
	}
	return nil
}

// GatherAttestations assembles the attestations pack required to run the
// evaluation. It first filters the attestations loaded manually by matching
// their descriptors against the chained subject and keeping those without
// a subject.
func (di *defaultIplementation) GatherAttestations(
	ctx context.Context, opts *VerificationOptions, agent *collector.Agent,
	policy *papi.Policy, subject attestation.Subject, attestations []attestation.Envelope,
) ([]attestation.Envelope, error) {
	// First, any predefined attestations (from the command line) need to be
	// filtered out as no subject matching is done. This is because we ingest
	// all of them in case they are needed when computing the chained subjects.

	// Apply gitCommit<->sha1 normalization to enable matching
	subject = normalizeSubjectDigests(subject, opts.GitCommitShaHack)
	digest := subject.GetDigest()

	// ... but we also need to keep the specified attestations that don't
	// have a subject. These come from bare json files, such as unsigned SBOMs
	attestations = attestation.NewQuery().WithFilter(
		&filters.SubjectHashMatcher{
			HashSets: []map[string]string{digest},
		},
		&filters.SubjectlessMatcher{},
	).Run(attestations, attestation.WithMode(attestation.QueryModeOr))

	// Pass any verification keys to the collector so it can verify
	// signatures on fetched attestations (e.g. keys embedded in policies). The
	// agent (and its key set) is shared across the concurrently-evaluated
	// policies and groups of a run, and AddKeys is not internally synchronized,
	// so guard it with the per-run evidence lock (nil outside a fan-out).
	if len(opts.Keys) > 0 {
		if mu := sharedEvidenceLock(ctx); mu != nil {
			mu.Lock()
			agent.AddKeys(opts.Keys...)
			mu.Unlock()
		} else {
			agent.AddKeys(opts.Keys...)
		}
	}

	// Now, query the collector to get all attestations available for the artifact.
	res, err := agent.FetchAttestationsBySubject(ctx, []attestation.Subject{subject})
	if err != nil {
		if !errors.Is(err, collector.ErrNoFetcherConfigured) {
			return nil, fmt.Errorf("collecting attestations: %w", err)
		} else {
			logrus.Warn(err)
			return []attestation.Envelope{}, nil
		}
	}
	return append(attestations, res...), nil
}

// ParseAttestations parses attestations loaded directly into the verifier to
// support the subject verification.
func (di *defaultIplementation) ParseAttestations(ctx context.Context, opts *VerificationOptions, subject attestation.Subject) ([]attestation.Envelope, error) {
	// Initialize the attestations set with any passed from the PolicySet verifier.
	res := opts.Attestations

	parsed, err := envelope.Parsers.ParseFiles(opts.AttestationFiles)
	if err != nil {
		return nil, fmt.Errorf("parsing attestations: %w", err)
	}

	// If the envelope is a bare JSON, we synthesize it by copying the
	// subject under verification as they were deemed applicable by the
	// user via the verifier flags.
	//
	// TODO(puerco): this should be an option passed to the collector parser
	for _, e := range parsed {
		if len(e.GetStatement().GetSubjects()) > 0 {
			res = append(res, e)
			continue
		}
		bareEnvelope, ok := e.(*bare.Envelope)
		if !ok {
			res = append(res, e)
			continue
		}
		// Since the statement interface has no set methods, we
		// need to cast it to set the data.
		s, ok := bareEnvelope.GetStatement().(*intoto.Statement)
		if !ok {
			res = append(res, e)
			continue
		}
		s.Subject = []*gointoto.ResourceDescriptor{
			{
				Name:   subject.GetName(),
				Uri:    subject.GetUri(),
				Digest: subject.GetDigest(),
			},
		}
		bareEnvelope.Statement = s
		res = append(res, bareEnvelope)
	}

	return res, nil
}

// AssertResult conducts the final assertion to allow/block based on the
// result sets returned by the evaluators.
func (di *defaultIplementation) AssertResult(policy *papi.Policy, result *papi.Result) error {
	switch policy.GetMeta().GetAssertMode() {
	case assertModeOR, "":
		for _, er := range result.EvalResults {
			if er.Status == papi.StatusPASS {
				result.Status = papi.StatusPASS
				return nil
			}
		}
		result.Status = papi.StatusFAIL
		if policy.GetMeta().GetEnforce() == enforceOFF {
			result.Status = papi.StatusSOFTFAIL
		}
	case assertModeAND:
		for _, er := range result.EvalResults {
			if er.Status == papi.StatusFAIL {
				result.Status = papi.StatusFAIL
				if policy.GetMeta().GetEnforce() == enforceOFF {
					result.Status = papi.StatusSOFTFAIL
				}
				return nil
			}
		}
		result.Status = papi.StatusPASS
	default:
		return fmt.Errorf("invalid policy assertion mode")
	}
	return nil
}

// BuildEvaluators checks a policy and build the required evaluators to run the tenets
func (di *defaultIplementation) BuildEvaluators(opts *VerificationOptions, p *papi.Policy) (map[class.Class]evaluator.Evaluator, error) {
	evaluators := map[class.Class]evaluator.Evaluator{}
	factory := evaluator.Factory{}
	var (
		defRT class.Class
		err   error
	)

	// Compute the default runtime, first from the options received.
	// If not set, then from the default options set.
	switch {
	case p.GetMeta().GetRuntime() != "":
		defRT, err = class.ParseClass(p.GetMeta().GetRuntime())
		if err != nil {
			return nil, fmt.Errorf("invalid policy runtime: %w", err)
		}
	case opts.DefaultEvaluator != "":
		defRT = opts.DefaultEvaluator
	default:
		defRT = DefaultVerificationOptions.DefaultEvaluator
	}

	e, err := factory.Get(&opts.EvaluatorOptions, defRT)
	if err != nil {
		return nil, fmt.Errorf("unable to build default runtime: %w", err)
	}
	logrus.Debugf("Registered default evaluator of class %s", defRT)
	evaluators[defaultEvaluatorClass] = e
	evaluators[defRT.BaseClass()] = e

	for _, link := range p.GetChain() {
		classString := link.GetPredicate().GetRuntime()
		if classString == "" {
			continue
		}
		chainRT, err := class.ParseClass(classString)
		if err != nil {
			return nil, fmt.Errorf("invalid chain predicate runtime: %w", err)
		}
		e, err := factory.Get(&opts.EvaluatorOptions, chainRT)
		if err != nil {
			return nil, fmt.Errorf("unable to build chained subject runtime")
		}
		logrus.Debugf("registered evaluator of class %s for chained predicate", classString)
		evaluators[chainRT.BaseClass()] = e
	}

	for _, t := range p.Tenets {
		if t.Runtime == "" {
			continue
		}
		rt, err := class.ParseClass(t.Runtime)
		if err != nil {
			return nil, fmt.Errorf("tenet %q has invalid runtime: %w", t.GetId(), err)
		}
		cl := rt.BaseClass()
		if _, ok := evaluators[cl]; ok {
			continue
		}
		e, err := factory.Get(&opts.EvaluatorOptions, rt)
		if err != nil {
			return nil, fmt.Errorf("building %q runtime: %w", t.Runtime, err)
		}
		evaluators[cl] = e
		logrus.Debugf("Registered evaluator of class %s", cl)
	}

	if len(evaluators) == 0 {
		return nil, errors.New("no valid runtimes found for policy tenets")
	}
	return evaluators, nil
}

// BuildTransformers
func (di *defaultIplementation) BuildTransformers(opts *VerificationOptions, policy *papi.Policy) (map[transformer.Class]transformer.Transformer, error) {
	factory := transformer.Factory{}
	transformers := map[transformer.Class]transformer.Transformer{}

	// Here we should have logic to support loading the latest version. So if
	// a policy defined v1 and we have v1.1 and v1.2 load v1.2. Also, no version
	// will load the latest version.
	for _, trDef := range policy.Transformers {
		t, err := factory.Get(transformer.Class(trDef.GetId()), trDef.GetConfig())
		if err != nil {
			return nil, fmt.Errorf("building tranformer for class %q: %w", t, err)
		}
		transformers[transformer.Class(trDef.GetId())] = t
	}

	logrus.Debugf("Loaded %d transformers defined in the policy", len(transformers))
	return transformers, nil
}

// Transform takes the predicates and a set of transformers and applies the transformations
// defined in the policy
func (di *defaultIplementation) Transform(
	opts *VerificationOptions, transformers map[transformer.Class]transformer.Transformer,
	policy *papi.Policy, subject attestation.Subject, prepredicates []attestation.Predicate,
) (attestation.Subject, []attestation.Predicate, error) {
	var err error
	var newsubject attestation.Subject
	i := 0
	for _, t := range transformers {
		newsubject, prepredicates, err = t.Mutate(subject, prepredicates)
		if newsubject != nil {
			subject = newsubject
		}
		if err != nil {
			return nil, nil, fmt.Errorf("applying transformation #%d (%T): %w", i, t, err)
		}
		i++
	}
	ts := []string{}
	for _, s := range prepredicates {
		ts = append(ts, string(s.GetType()))
	}
	logrus.Debugf("Predicate types after transform: %v", ts)
	return subject, prepredicates, nil
}

// admission records the outcome of CheckIdentities for one envelope: whether
// it may be used as evidence, whether its signature verified, and, when an
// identity constraint applies, the allowed identities its signer matched.
type admission struct {
	admitted   bool
	verified   bool
	identities []*sapi.Identity
}

// CheckIdentities verifies attestation signatures and decides which envelopes
// are admitted as evidence. Admission is a two stage gate whose outcome does
// not depend on how an attestation was signed:
//
//  1. Signature: an envelope is admitted only when its signature verified
//     against the available material (the sigstore trust roots for bundles,
//     the configured public keys for DSSE envelopes). Bare statements and
//     envelopes signed with keys the verifier does not hold are unverified,
//     not errors.
//     The one exception is opts.AdmitUnverified, which admits unverified envelopes
//     the caller passed explicitly when no identity constraint applies (see
//     withExplicitEvidence). Evidence fetched by the collector is never admitted
//     unverified.
//
//  2. Identity: when the policy (or the options, if the policy defines none)
//     pins signer identities, a verified envelope is admitted only if its
//     signer matches one of them.
//
// Envelopes that fail either gate are dropped from the evidence set. The
// returned slice carries one admission per envelope. The boolean is false when
// nothing was admitted although evidence was supplied (or an identity
// constraint applies), and the error list then explains why nothing was admitted:
// an identity mismatch, or ErrUnverifiedAttestations when every envelope was
// unverified.
func (di *defaultIplementation) CheckIdentities(ctx context.Context, opts *VerificationOptions, policyIdentities []*sapi.Identity, envelopes []attestation.Envelope) (bool, []admission, []error, error) {
	// allIds are the allowed ids (from the policy + any from options)
	allIds := []*sapi.Identity{}

	// Extract any identities received in the context
	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if ok {
		allIds = evalContext.Identities
	}

	allIds = append(allIds, policyIdentities...)

	if len(policyIdentities) > 0 && len(opts.IdentityStrings) > 0 {
		logrus.Warnf(
			"Policy has signer identities defined, %d identities from options will be ignored",
			len(opts.IdentityStrings))
	}

	// Add any identities defined in options
	if len(opts.IdentityStrings) > 0 && len(policyIdentities) == 0 {
		logrus.Debugf("Got %d identity strings from options", len(opts.IdentityStrings))
		for _, idSlug := range opts.IdentityStrings {
			ident, err := sapi.NewIdentityFromSpec(idSlug)
			if err != nil {
				return false, nil, nil, fmt.Errorf("invalid identity slug %q: %w", idSlug, err)
			}
			allIds = append(allIds, ident)
		}
	}

	constrained := len(allIds) > 0
	if constrained {
		logrus.Debug("Will look for signed attestations from:")
		for _, i := range allIds {
			logrus.Debugf("  > %s", i.Principal())
		}
	} else {
		logrus.Debug("No identities defined in policy. Not filtering on signer identity.")
	}

	// The keys to use are the ones in the options...
	keys := opts.Keys

	// Plus any defined in the policy
	for _, id := range policyIdentities {
		k, err := id.PublicKey()
		if err != nil {
			return false, nil, nil, fmt.Errorf("parsing identity key: %w", err)
		}
		if k != nil {
			keys = append(keys, k)
		}
	}

	// Verify signatures and decide the admission of each envelope. The
	// envelopes are shared across the concurrently-evaluated policies of a
	// PolicySet, and their verification is cached/recomputed on the shared
	// predicate, so serialize the verify-and-match step under the per-run lock
	// published on the context (nil outside a concurrent fan-out).
	admissions := make([]admission, len(envelopes))

	// observedSigners collects the actual signer identities seen on the
	// verified attestations. It is used to build a "wanted / got" diagnostic
	// when no attestation matches an accepted identity.
	var observedSigners []*sapi.Identity
	admitted, unverified := 0, 0
	if mu := sharedEvidenceLock(ctx); mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	for i, e := range envelopes {
		ptype := e.GetStatement().GetPredicateType()
		if err := e.Verify(keys); err != nil {
			logrus.Debugf("attestation %d (type %s): signature verification error, skipping: %v", i, ptype, err)
			unverified++
			continue
		}

		// Signature gate. Verify records the outcome on the envelope. It does
		// not fail on a bad or unverifiable signature.
		v := e.GetVerification()
		if v == nil || !v.GetVerified() {
			unverified++
			if !constrained && opts.AdmitUnverified && isExplicitEvidence(ctx, e) {
				logrus.Warnf("attestation %d (type %s) is unsigned or its signature could not be verified; admitting it because it was passed explicitly", i, ptype)
				admissions[i] = admission{admitted: true}
				admitted++
				continue
			}
			logrus.Debugf("attestation %d (type %s): not verified, skipping", i, ptype)
			continue
		}
		observedSigners = append(observedSigners, envelopeSigners(e)...)

		if !constrained {
			admissions[i] = admission{admitted: true, verified: true}
			admitted++
			continue
		}

		// Identity gate.
		var matched []*sapi.Identity
		for _, id := range allIds {
			if v.MatchesIdentity(id) {
				matched = append(matched, id)
			}
		}
		if len(matched) == 0 {
			logrus.Debugf("attestation %d (type %s): no matching signer identity, skipping", i, ptype)
			continue
		}
		admissions[i] = admission{admitted: true, verified: true, identities: matched}
		admitted++
	}

	if admitted > 0 {
		return true, admissions, nil, nil
	}
	if constrained {
		return false, admissions, []error{
			identityMismatchError(allIds, observedSigners, unverified),
		}, nil
	}
	if len(envelopes) == 0 {
		return true, admissions, nil, nil
	}
	return false, admissions, []error{
		fmt.Errorf("%w: %d attestation(s) were unsigned or signed with keys the verifier does not hold", ErrUnverifiedAttestations, unverified),
	}, nil
}

// identityMismatchError builds a human-readable "wanted / got" diagnostic for a
// signer-identity check that admitted no attestations. The wanted identities are
// rendered in their rich (matcher-aware) form while the observed signers are
// recorded as pure principals. "unverified" counts the attestations skipped
// because their signature did not verify, so an operator can tell a missing key
// apart from a wrong signer.
func identityMismatchError(wanted, got []*sapi.Identity, unverified int) error {
	var err error
	if len(got) == 0 {
		err = fmt.Errorf(
			"no attestation carried a verified signer identity (wanted one of: %s)",
			renderIdentities(wanted, (*sapi.Identity).Spec),
		)
	} else {
		err = fmt.Errorf(
			"attestation signer does not match an accepted identity (wanted one of: %s; got: %s)",
			renderIdentities(wanted, (*sapi.Identity).Spec),
			renderIdentities(got, (*sapi.Identity).Principal),
		)
	}
	if unverified > 0 {
		err = fmt.Errorf("%w; %d attestation(s) were skipped because they are unsigned or their signature could not be verified", err, unverified)
	}
	return err
}

// renderIdentities renders a list of identities to a comma separated string
// using the provided rendering function, de-duplicating and dropping empties.
func renderIdentities(ids []*sapi.Identity, render func(*sapi.Identity) string) string {
	seen := make(map[string]struct{}, len(ids))
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		s := render(id)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ", ")
}

// FilterAttestations turns the envelopes admitted by CheckIdentities into the
// predicates a policy evaluates, stamping each with the verification outcome
// CheckIdentities recorded: whether the signature verified and the allowed
// identities the signer matched. Envelopes that were not admitted are excluded.
//
// The verification data is exposed to the evaluator through a per-policy
// matchedPredicate wrapper rather than by mutating the shared predicate.
func (di *defaultIplementation) FilterAttestations(opts *VerificationOptions, subject attestation.Subject, envs []attestation.Envelope, admissions []admission) ([]attestation.Predicate, error) {
	if len(admissions) != len(envs) {
		return nil, fmt.Errorf("admission list does not match the envelope list (%d admissions for %d envelopes)", len(admissions), len(envs))
	}
	preds := make([]attestation.Predicate, 0, len(envs))
	for i, env := range envs {
		// Skip envelopes that were not admitted by CheckIdentities.
		if !admissions[i].admitted {
			continue
		}
		preds = append(preds, &matchedPredicate{
			Predicate: env.GetStatement().GetPredicate(),
			verification: &sapi.Verification{
				Signature: &sapi.SignatureVerification{
					Date:       timestamppb.Now(),
					Verified:   admissions[i].verified,
					Identities: admissions[i].identities,
				},
			},
			// Carry the attestation's actual verified signers, independent of
			// the matched allowlist subset above. These are populated even when
			// no allowlist is configured and are surfaced to policies as
			// verification.signers.
			signers: envelopeSigners(env),
		})
	}
	return preds, nil
}

// envelopeSigners returns the actual verified signer identities recorded on an
// envelope's verification, tolerating a nil/absent verification by returning
// nil. Unlike the matched allowlist subset carried on matchedPredicate's
// verification, these are the real signers AMPEL observed regardless of whether
// an allowlist was pinned.
func envelopeSigners(env attestation.Envelope) []*sapi.Identity {
	v, ok := env.GetVerification().(*sapi.Verification)
	if !ok || v == nil {
		return nil
	}
	return v.GetSignature().GetIdentities()
}

// matchedPredicate wraps a shared attestation.Predicate to carry the identities
// the signer matched for a single policy without mutating the underlying
// predicate, which is shared across the policies of a PolicySet. It overrides
// the verification accessors so the evaluator sees the per-policy matched
// identities while leaving the shared predicate (and the signer identity cached
// on its envelope) untouched. See FilterAttestations and issue #298.
//
// It additionally carries the attestation's actual verified signers so policies
// can read who really signed (via verification.signers in CEL) regardless of
// whether an allowlist was pinned. This satisfies cel.SignersProvider.
type matchedPredicate struct {
	attestation.Predicate
	verification attestation.Verification
	// signers holds the actual verified signer identities observed on the
	// attestation envelope. It is distinct from the matched allowlist subset
	// carried on verification (which is empty when no allowlist was supplied)
	// and is surfaced to the evaluator as verification.signers.
	signers []*sapi.Identity
}

func (mp *matchedPredicate) GetVerification() attestation.Verification {
	return mp.verification
}

func (mp *matchedPredicate) SetVerification(v attestation.Verification) {
	mp.verification = v
}

// Signers returns the actual verified signer identities of the attestation.
// The CEL verification adapter reads these (via cel.SignersProvider) to
// populate verification.signers. It is an AMPEL-provided view and is NOT part
// of the carabiner-dev/signer Verification proto.
func (mp *matchedPredicate) Signers() []*sapi.Identity {
	return mp.signers
}

// Compile-time assertion that matchedPredicate satisfies the CEL adapter's
// SignersProvider contract, keeping the FilterAttestations → CEL plumbing intact.
var _ cel.SignersProvider = (*matchedPredicate)(nil)

// evaluateChain evaluates an evidence chain and returns the resulting subject
func (di *defaultIplementation) evaluateChain(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	agent *collector.Agent, chainLinks []*papi.ChainLink, evalContextValues map[string]any, subject attestation.Subject,
	attestations []attestation.Envelope, globalIdentities []*sapi.Identity, defaultEvalClass string,
) ([]attestation.Subject, []*papi.ChainedSubject, bool, error) {
	chain := []*papi.ChainedSubject{}
	logrus.Debug("Processing evidence chain")
	var subjectsList []attestation.Subject

	// Cycle all links and eval
	for i, link := range chainLinks {
		var lattestation []attestation.Envelope
		logrus.Debugf(" Link needs %s", link.GetPredicate().GetType())

		// Apply gitCommit<->sha1 normalization to the subject before matching
		// This ensures evidence chains work with both sha1: and gitCommit: digest types
		normalizedSubject := normalizeSubjectDigests(subject, opts.GitCommitShaHack)

		// Build an attestation query for the type we need but filter
		// the attestations to only the current computed subject.
		q := attestation.NewQuery().WithFilter(
			&filters.PredicateTypeMatcher{
				PredicateTypes: map[attestation.PredicateType]struct{}{
					attestation.PredicateType(link.GetPredicate().GetType()): {},
				},
			},
			// TODO(puerco): Filter on the whole subject (not just hashes).
			&filters.SubjectHashMatcher{
				HashSets: []map[string]string{normalizedSubject.GetDigest()},
			},
		)

		lattestation = q.Run(attestations)

		// Only fetch more attestations from the configured sources if we need more:
		if len(lattestation) == 0 && agent != nil {
			moreatts, err := agent.FetchAttestationsBySubject(
				ctx, []attestation.Subject{normalizedSubject}, collector.WithQuery(q),
			)
			if err != nil {
				return nil, nil, false, fmt.Errorf("collecting attestations: %w", err)
			}
			lattestation = append(lattestation, moreatts...)
		}

		if len(lattestation) == 0 {
			return nil, nil, true, PolicyError{
				error:    fmt.Errorf("no matching attestations to read the chained subject #%d", i),
				Guidance: "make sure the collector has access to attestations to satisfy the subject chain as defined in the policy.",
			}
		}

		// Here, we warn if we get more than one attestation for the chained
		// predicate. Probably this should be limited to only one.
		if len(lattestation) > 1 {
			logrus.Debugf("WARN: Chained subject builder got more than one matching statement")
		}

		if err := lattestation[0].Verify(opts.Keys); err != nil {
			return nil, nil, true, PolicyError{
				error:    fmt.Errorf("signature verifying failed in chained subject: %w", err),
				Guidance: "the signature verification in the loaded attestations failed, try resigning it",
			}
		}
		var pass bool
		var err error
		var ids []admission

		// Check the attestation identities for now, we fallback to the identities
		// defined in the policy if the link does not have its own. Probably this
		// should have a better default.
		chainIdentities := globalIdentities
		if link.GetPredicate().GetIdentities() != nil {
			chainIdentities = link.GetPredicate().GetIdentities()
		}
		// Resolve any from_context bindings so the feature also reaches
		// chained-predicate identities and fails closed on a missing value.
		chainIdentities, err = resolvePolicyIdentities(chainIdentities, evalContextValues)
		if err != nil {
			return nil, nil, false, fmt.Errorf("resolving chained attestation identity: %w", err)
		}
		pass, ids, _, err = di.CheckIdentities(ctx, opts, chainIdentities, lattestation[0:0])
		if err != nil {
			return nil, nil, false, fmt.Errorf("error checking attestation identity: %w", err)
		}
		if !pass {
			return nil, nil, true, PolicyError{
				error:    fmt.Errorf("unable to validate chained attestation identity"),
				Guidance: "the chained attestaion identity does not match the policy",
			}
		}

		// TODO: Mueve a metodos en policy.go
		classString := link.GetPredicate().GetRuntime()
		if classString == "" {
			classString = defaultEvalClass
		}

		key := classForRuntime(classString)
		if key == "" && opts.DefaultEvaluator != "" {
			key = opts.DefaultEvaluator.BaseClass()
		}
		if _, ok := evaluators[key]; !ok {
			return nil, nil, false, fmt.Errorf("no evaluator loaded for class %s", key)
		}

		// Populate the context data
		ectx, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
		if !ok {
			ectx = evalcontext.EvaluationContext{}
		}
		ectx.Subject = subject
		ectx.ContextValues = evalContextValues
		ctx := context.WithValue(ctx, evalcontext.EvaluationContextKey{}, ectx)

		// Execute the selector
		subjectsList, err = evaluators[key].ExecChainedSelector(
			ctx, &opts.EvaluatorOptions, link.GetPredicate(),
			lattestation[0].GetStatement().GetPredicate(),
		)
		if err != nil {
			// TODO(puerco): The false here instructs ampel to return an error
			// (not a policy fail) when there is a syntax error in the policy
			// code (CEL or otherwise). Perhaps this should be configurable.
			return nil, nil, false, fmt.Errorf("evaluating chained subject code: %w", err)
		}

		// If we've evaluated the chain until the end, we return the empty list
		// and don't err. Throwing an error is up to the calling function.
		if len(subjectsList) == 0 {
			if i == len(chainLinks)-1 {
				return subjectsList, chain, false, nil
			}
			return nil, nil, false, fmt.Errorf("failed to obtain a subject to fullfil predicate chain")
		}

		// All intermediate links MUST return only one subject because they point
		// to a new subject. Only the last link can return many subjects as
		// a PolicySet can fan out to point to many,
		if i+1 != len(chainLinks) && len(subjectsList) != 1 {
			return nil, nil, false, fmt.Errorf("chained selector must return exactly one subject (got %d)", len(subjectsList))
		}

		// Add to link history
		var goodIds []*sapi.Identity
		if len(ids) > 0 {
			goodIds = ids[0].identities
		}
		chain = append(chain, &papi.ChainedSubject{
			Source:      newResourceDescriptorFromSubject(subject),
			Destination: newResourceDescriptorFromSubject(subjectsList[0]),
			Link: &papi.ChainedSubjectLink{
				Type:        string(lattestation[0].GetStatement().GetPredicateType()),
				Attestation: newResourceDescriptorFromSubject(lattestation[0].GetPredicate().GetOrigin()),
				Identities:  goodIds,
			},
		})
		subject = subjectsList[0]
	}
	return subjectsList, chain, false, nil
}

// SelectChainedSubject returns a new subkect from an ingested attestatom
func (di *defaultIplementation) ProcessChainedSubjects(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	agent *collector.Agent, material papi.ChainProvider, evalContextValues map[string]any, subject attestation.Subject,
	attestations []attestation.Envelope,
) (attestation.Subject, []*papi.ChainedSubject, bool, error) {
	// If there are no chained subjects, return the original
	if material.GetChain() == nil {
		return subject, []*papi.ChainedSubject{}, false, nil
	}

	defaultEvalClass := ""
	ids := []*sapi.Identity{}

	switch p := material.(type) {
	case *papi.Policy:
		// Get the default evaluator from the policy
		if p.GetMeta() != nil {
			defaultEvalClass = p.GetMeta().GetRuntime()
		}

		// Here, we only pass the policy, the context will be completed on each eval
		ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalcontext.EvaluationContext{
			Policy: p,
		})

		ids = p.GetIdentities()
	case *papi.PolicyGroup:
		// Get the default evaluator from the policy
		if p.GetMeta() != nil {
			defaultEvalClass = p.GetMeta().GetRuntime()
		}
		ids = p.GetCommon().GetIdentities()
	}

	subjects, chain, fail, err := di.evaluateChain(
		ctx, opts, evaluators, agent, material.GetChain(), evalContextValues, subject,
		attestations, ids, defaultEvalClass,
	)
	if err != nil {
		return nil, nil, fail, err
	}

	if len(subjects) > 1 {
		return nil, nil, false, fmt.Errorf("processing chained subjects returned more than one subject")
	}

	if len(subjects) == 0 {
		return nil, nil, false, fmt.Errorf("unable to complete evidence chain, no subject returned")
	}

	// If we got a precomputed chain (from the policy set) it precedes the
	// policy computed at the policy level.
	// Add the (eval) context, to the (go) context :P
	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if ok {
		if evalContext.ChainedSubjects != nil {
			chain = slices.Concat(evalContext.ChainedSubjects, chain)
		}
	}

	return subjects[0], chain, fail, nil
}

func newResourceDescriptorFromSubject(s attestation.Subject) *gointoto.ResourceDescriptor {
	if s == nil {
		return nil
	}
	return &gointoto.ResourceDescriptor{
		Name:   s.GetName(),
		Uri:    s.GetUri(),
		Digest: s.GetDigest(),
	}
}

// mergeContextValClone returns base with over merged into it, without mutating
// base. base may be a *papi.ContextVal shared by reference across the
// concurrently evaluated policies of a run (e.g. inherited from the PolicySet
// common context), so it is cloned before merging (issue #298).
func mergeContextValClone(base, over *papi.ContextVal) *papi.ContextVal {
	merged, ok := proto.Clone(base).(*papi.ContextVal)
	if !ok {
		// proto.Clone of a *papi.ContextVal always returns a *papi.ContextVal;
		// rebuild from base on the unreachable miss so we still never mutate it.
		merged = &papi.ContextVal{}
		merged.Merge(base)
	}
	merged.Merge(over)
	return merged
}

// AssembleEvalContextValues puts together the context values map by assembling
// the context definition starting with its defaults, received values from
// upstream and context value providers.
func (di *defaultIplementation) AssembleEvalContextValues(
	ctx context.Context, opts *VerificationOptions,
	evaluators map[class.Class]evaluator.Evaluator,
	contextValues map[string]*papi.ContextVal,
) (map[string]any, error) {
	errs := []error{}

	// Load the context definitions as received from invocation
	values := map[string]any{}
	assembledContext := map[string]*papi.ContextVal{}

	// Context names can be any case, but they cannot clash when normalized
	// to lower case. This means that both MyValue and myvalue are valid names
	// but you cannot have both at the same time.
	lcnames := map[string]string{}
	fromParent := map[string]struct{}{} // This is to track if the value vas defined at the parent

	// Things using AMPEL send the definitions in the context
	preContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if ok {
		if preContext.ContextValues != nil {
			logrus.Warnf("Eval context has preloaded values. They will be discarded")
		}

		// Assemble the context structure from the struct received from ancestors
		// (eg if its coming from a PolicySet commons)
		if preContext.Context != nil {
			for k, v := range preContext.Context {
				// Validate key?
				assembledContext[k] = v
				if existingName, ok := lcnames[strings.ToLower(k)]; ok {
					if existingName != k {
						return nil, fmt.Errorf("parent context value name %q clashes with existing name %q", k, lcnames[strings.ToLower(k)])
					}
				}
				lcnames[strings.ToLower(k)] = k
				fromParent[k] = struct{}{}
			}
		}
	}

	// Override the ancestor context structure with the policy context
	// definition (if any)
	for k, def := range contextValues {
		// Check if there is an existing value name that clashed with this one
		// when normalized to lowercase
		if existingName, ok := lcnames[strings.ToLower(k)]; ok {
			if existingName != k {
				// Here choose which error to return
				if _, ok := fromParent[k]; ok {
					return nil, fmt.Errorf("context value name %q clashes with %q coming from parent context", k, lcnames[strings.ToLower(k)])
				}
				return nil, fmt.Errorf("context value name %q clashes with existing name %q", k, lcnames[strings.ToLower(k)])
			}
		}
		lcnames[strings.ToLower(k)] = k
		// Validate the key? Probably in a policy validation func
		if existing, ok := assembledContext[k]; ok {
			// The existing value may be inherited from the PolicySet common
			// context, which is shared by reference across the concurrently
			// evaluated policies. Merge into a clone so the policy's own
			// context definition never mutates that shared object (issue #298).
			assembledContext[k] = mergeContextValClone(existing, def)
		} else {
			assembledContext[k] = def
		}
	}

	// Get the values from the configured providers
	definitions, err := acontext.GetValues(opts.ContextProviders, slices.Collect(maps.Keys(assembledContext)))
	if err != nil {
		return nil, fmt.Errorf("getting values from providers: %w", err)
	}

	logrus.Debugf("[CTX] Assembled Context: %+v", assembledContext)
	logrus.Debugf("[CTX] Context Values: %+v", definitions)

	// Resolution is done in two phases over a stable, sorted key order:
	//
	//   Phase 1 — resolve every static entry (value, default, provider).
	//   Snapshot — publish the Phase 1 results onto the evalcontext so they
	//              are reachable from CEL as `context.<name>`.
	//   Phase 2 — resolve every expression entry with the static-only
	//             snapshot in scope. Expression results are NOT added to the
	//             snapshot, so sibling expressions cannot observe each other.
	//
	// Sorting both phases makes ordering deterministic and keeps any errors
	// reported in a stable order.
	sortedKeys := slices.Sorted(maps.Keys(assembledContext))

	// Phase 1: static values.
	for _, k := range sortedKeys {
		contextDef := assembledContext[k]
		if contextDef.GetExpression() != "" {
			continue
		}
		var v any
		// Burned-in value wins outright; cannot be overridden by callers.
		if contextDef.Value != nil {
			values[k] = contextDef.Value.AsInterface()
			continue
		}

		// Default is the overridable base.
		if contextDef.Default != nil {
			v = contextDef.Default.AsInterface()
		}

		// Provider-supplied values override the default.
		if _, ok := definitions[k]; ok {
			v = definitions[k]
		}

		values[k] = v

		// Required values must end Phase 1 with a non-nil value; expression
		// values are checked separately in Phase 2.
		if contextDef.Required != nil && *contextDef.Required && values[k] == nil {
			errs = append(errs, fmt.Errorf("context value %s is required but not set", k))
		}
	}

	// Phase 2: dynamic values resolved by an evaluator runtime. We publish a
	// snapshot of the Phase 1 results onto the evalcontext so that CEL
	// expressions see them via `context.<name>`. The snapshot is built once
	// and never mutated, so expressions cannot depend on each other.
	hasExpressions := false
	for _, contextDef := range assembledContext {
		if contextDef.GetExpression() != "" {
			hasExpressions = true
			break
		}
	}
	if hasExpressions {
		exprCtx := ctx
		if ec, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext); ok {
			snapshot := make(map[string]any, len(values))
			maps.Copy(snapshot, values)
			ec.ContextValues = snapshot
			exprCtx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, ec)
		}

		for _, k := range sortedKeys {
			contextDef := assembledContext[k]
			expr := contextDef.GetExpression()
			if expr == "" {
				continue
			}
			cls := classForRuntime(contextDef.GetRuntime())
			if cls == "" {
				cls = defaultEvaluatorClass
			}
			ev, ok := evaluators[cls]
			if !ok {
				errs = append(errs, fmt.Errorf("context value %q: runtime %q not available", k, cls))
				continue
			}
			out, err := ev.EvalExpression(exprCtx, &opts.EvaluatorOptions, expr)
			if err != nil {
				errs = append(errs, fmt.Errorf("evaluating expression for context value %q: %w", k, err))
				continue
			}
			values[k] = out

			if contextDef.Required != nil && *contextDef.Required && values[k] == nil {
				errs = append(errs, fmt.Errorf("context value %s is required but not set", k))
			}
		}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	// Ensure context values are in the correct type when typed. For now, we
	// enforce and cross convert simple types: string, int and bool and
	// force-convert between them. This means that if a value is typed in
	// the context definition, the evaluator is guaranteed to get it in
	// that type or ampel will return an error before evaluating.
	//
	// Ideally, context providers will return these in their correct types
	// but we ensure they are correct here to guarantee evaluators get the
	// context values in the right types.
	for k, contextDef := range assembledContext {
		typedVal, err := ensureContextType(values[k], contextDef)
		if err != nil {
			errs = append(errs, err)
		}
		values[k] = typedVal
	}

	return values, errors.Join(errs...)
}

// VerifySubject performs the core verification of attested data. This step runs after
// all gathering, parsing, transforming and verification is performed.
func (di *defaultIplementation) VerifySubject(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	p *papi.Policy, evalContextValues map[string]any, subject attestation.Subject, prepredicates []attestation.Predicate,
) (*papi.Result, error) {
	evalContextValuesStruct, err := structpb.NewStruct(evalContextValues)
	if err != nil {
		return nil, fmt.Errorf("serializing evaluation context data: %w", err)
	}
	rs := &papi.Result{
		DateStart: timestamppb.Now(),
		Policy: &papi.PolicyRef{
			Id: p.Id,
		},
		Meta: p.GetMeta(),
		Subject: &gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		},
		Context: evalContextValuesStruct,
	}

	evalOpts := &options.EvaluatorOptions{}

	errs := []error{}

	// Start building the required policy types extracting those at the policy level
	policyPredMap := map[attestation.PredicateType]struct{}{}
	for _, tp := range p.GetPredicates().GetTypes() {
		policyPredMap[attestation.PredicateType(tp)] = struct{}{}
	}

	// Populate the context data
	ctx = context.WithValue(
		ctx, evalcontext.EvaluationContextKey{},
		evalcontext.EvaluationContext{
			Subject:       subject,
			Policy:        p,
			ContextValues: evalContextValues,
		},
	)

	for i, tenet := range p.Tenets {
		key := classForRuntime(tenet.Runtime)
		if key == "" {
			key = defaultEvaluatorClass
		}

		// Filter the predicates to those requested by the tenet or the policy:
		npredicates := []attestation.Predicate{}
		idx := map[attestation.PredicateType]struct{}{}
		maps.Insert(idx, maps.All(policyPredMap))

		// Add any predicate types defined at the tenet level
		for _, tp := range tenet.GetPredicates().GetTypes() {
			idx[attestation.PredicateType(tp)] = struct{}{}
		}

		for _, pred := range prepredicates {
			if _, ok := idx[pred.GetType()]; ok {
				npredicates = append(npredicates, pred)
			}
		}

		skipEval := false
		var evalres *papi.EvalResult

		// If the tenet requires predicates but we don't have any, then
		// error here and skip the eval altogether.
		if len(idx) > 0 && len(npredicates) == 0 {
			evalres = &papi.EvalResult{
				Status:     papi.StatusFAIL,
				Date:       timestamppb.Now(),
				Statements: []*papi.StatementRef{},
				Error: &papi.Error{
					Message:  ErrMissingAttestations.Error(),
					Guidance: fmt.Sprintf("Missing attestations to evaluate the policy on %s", subjectToString(subject)),
				},
			}
			skipEval = true
			if opts.ErrOnMissingAttestations {
				errs = append(errs, fmt.Errorf("tenet #%d on subject %s: %w", i, subjectToString(subject), ErrMissingAttestations))
			}
		}

		if !skipEval {
			evalres, err = evaluators[key].ExecTenet(ctx, evalOpts, tenet, npredicates)
			if err != nil {
				errs = append(errs, fmt.Errorf("executing tenet #%d: %w", i, err))
				continue
			}
		}
		logrus.WithField("tenet", i).Debugf("Result: %+v", evalres)

		// TODO(puerco): Ideally, we should not reach here with unparseable templates but oh well..
		// See https://github.com/carabiner-dev/policy/issues/4

		// This is the data that gets exposed to error and assessment templates
		templateData := struct {
			Status  string
			Context map[string]any
			Outputs map[string]any
			Subject *gointoto.ResourceDescriptor
		}{
			Status:  evalres.GetStatus(),
			Context: evalContextValues,
			Outputs: evalres.GetOutput().AsMap(),
			Subject: &gointoto.ResourceDescriptor{
				Name:   subject.GetName(),
				Uri:    subject.GetUri(),
				Digest: subject.GetDigest(),
			},
		}

		// Carry over the error from the policy if the runtime didn't add one
		if evalres.GetStatus() != papi.StatusPASS && evalres.GetError() == nil {
			var b, b2 bytes.Buffer

			tmplMsg, err := template.New("error_message").Parse(tenet.Error.GetMessage())
			if err != nil {
				return nil, fmt.Errorf("parsing tenet error template: %w", err)
			}
			if err := tmplMsg.Execute(&b, templateData); err != nil {
				return nil, fmt.Errorf("executing error message template: %w", err)
			}

			tmpl, err := template.New("error_guidance").Parse(tenet.Error.GetGuidance())
			if err != nil {
				return nil, fmt.Errorf("parsing tenet guidance template: %w", err)
			}
			if err := tmpl.Execute(&b2, templateData); err != nil {
				return nil, fmt.Errorf("executing error guidance template: %w", err)
			}

			evalres.Error = &papi.Error{
				Message:  b.String(),
				Guidance: b2.String(),
			}
		}

		// Carry over the assessment from the policy if not set by the runtime
		if evalres.GetStatus() == papi.StatusPASS && evalres.Assessment == nil {
			tmpl, err := template.New("assessment").Parse(tenet.Assessment.GetMessage())
			if err != nil {
				return nil, fmt.Errorf("parsing tenet assessment: %w", err)
			}
			var b bytes.Buffer
			if err := tmpl.Execute(&b, templateData); err != nil {
				return nil, fmt.Errorf("executing assessment template: %w", err)
			}
			evalres.Assessment = &papi.Assessment{
				Message: b.String(),
			}
		}

		rs.EvalResults = append(rs.EvalResults, evalres)
	}

	// Stamp the end date
	rs.DateEnd = timestamppb.Now()

	return rs, errors.Join(errs...)
}

// ProcessPolicySetChainedSubjects executes a PolicySet's ChainLink and returns
// the resulting list of subjects from the evaluator.
func (di *defaultIplementation) ProcessPolicySetChainedSubjects(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	agent *collector.Agent, policySet *papi.PolicySet, evalContextValues map[string]any, subject attestation.Subject,
	attestations []attestation.Envelope,
) ([]attestation.Subject, []*papi.ChainedSubject, bool, error) {
	chain := []*papi.ChainedSubject{}

	// If there are no chained subjects, then the list of subject contains only
	// the original subject. If there is a chain defined, then the subject will
	// be replaced with the list of data extracted from the chain's attesations.
	if policySet.GetChain() == nil {
		return []attestation.Subject{subject}, chain, false, nil
	}

	// Get the default evaluator from the policy
	defaultEvalClass := ""
	if policySet.GetMeta() != nil {
		defaultEvalClass = policySet.GetMeta().GetRuntime()
	}

	subjects, chain, fail, err := di.evaluateChain(
		ctx, opts, evaluators, agent, policySet.GetChain(), evalContextValues, subject,
		attestations, policySet.GetCommon().GetIdentities(), defaultEvalClass,
	)
	if err != nil {
		return nil, nil, fail, err
	}

	return subjects, chain, fail, nil
}

func (di *defaultIplementation) BuildGroupEvaluators(opts *VerificationOptions, grp *papi.PolicyGroup) (map[class.Class]evaluator.Evaluator, error) {
	// Build the required evaluators
	evaluators := map[class.Class]evaluator.Evaluator{}

	for _, block := range grp.GetBlocks() {
		for _, p := range block.GetPolicies() {
			policyEvals, err := di.BuildEvaluators(opts, p)
			if err != nil {
				return nil, fmt.Errorf("building evaluators: %w", err)
			}
			maps.Insert(evaluators, maps.All(policyEvals))
		}
	}
	return evaluators, nil
}

// classForRuntime parses a raw runtime string and returns its base evaluator
// class. Returns "" for an empty string; logs a warning and returns "" on
// parse failure so callers can fall through to their own default.
func classForRuntime(runtimeStr string) class.Class {
	if runtimeStr == "" {
		return ""
	}
	rt, err := class.ParseClass(runtimeStr)
	if err != nil {
		logrus.Warnf("invalid runtime %q, using default evaluator: %v", runtimeStr, err)
		return ""
	}
	return rt.BaseClass()
}
