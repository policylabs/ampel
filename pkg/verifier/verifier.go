// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/nozzle/throttler"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
	sapi "github.com/policylabs/signer/api/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/policylabs/ampel/pkg/attest"
	"github.com/policylabs/ampel/pkg/evaluator"
	"github.com/policylabs/ampel/pkg/evaluator/class"
	"github.com/policylabs/ampel/pkg/evaluator/evalcontext"
)

const (
	assertModeAND = "AND"
	assertModeOR  = "OR"
	enforceOFF    = "OFF"
)

type PolicyError struct {
	error
	Guidance string
}

// sharedEvidenceLockKey is the context key under which VerifySubjectWithPolicySet
// publishes a per-run mutex. The policies and groups of a set are evaluated
// concurrently but share evidence-handling state: the attestation envelopes
// (whose Verify() caches/recomputes verification on the shared predicate) and
// the collector agent (whose AddKeys mutates a shared key set). The lock
// serializes mutation of that shared state for one run; it is scoped to the run
// (not the verifier) so unrelated runs proceed in parallel. See
// sharedEvidenceLock and issue #298.
type sharedEvidenceLockKey struct{}

// sharedEvidenceLock returns the per-run evidence lock published on the context,
// or nil when none is set. A nil lock means the caller is not part of a
// concurrent fan-out (e.g. a single policy verified directly), so the shared
// envelopes and collector are not at risk and no locking is required.
func sharedEvidenceLock(ctx context.Context) *sync.Mutex {
	mu, ok := ctx.Value(sharedEvidenceLockKey{}).(*sync.Mutex)
	if !ok {
		return nil
	}
	return mu
}

// explicitEvidenceKey is the context key under which the verifier publishes
// the set of envelopes the caller passed explicitly (opts.Attestations and
// opts.AttestationFiles), as opposed to evidence fetched by the collector. Only
// these are eligible for the AdmitUnverified opt-in in CheckIdentities.
type explicitEvidenceKey struct{}

// withExplicitEvidence records the explicitly supplied envelopes on the context.
func withExplicitEvidence(ctx context.Context, envs []attestation.Envelope) context.Context {
	set := make(map[attestation.Envelope]struct{}, len(envs))
	for _, e := range envs {
		set[e] = struct{}{}
	}
	return context.WithValue(ctx, explicitEvidenceKey{}, set)
}

// isExplicitEvidence reports whether env was passed explicitly to the verifier.
func isExplicitEvidence(ctx context.Context, env attestation.Envelope) bool {
	set, ok := ctx.Value(explicitEvidenceKey{}).(map[attestation.Envelope]struct{})
	if !ok {
		return false
	}
	_, ok = set[env]
	return ok
}

// Verify checks a subject against a policy using the available evidence. The
// policy argument may be a single policy, a policy group or a policy set; the
// results are published once per call, regardless of the material kind.
func (ampel *Ampel) Verify(
	ctx context.Context, opts *VerificationOptions, policy any, subject attestation.Subject,
) (papi.Results, error) {
	results, err := ampel.verify(ctx, opts, policy, subject)
	if err != nil {
		return nil, err
	}

	// Publish the results (best-effort): the publisher fans them out to the
	// configured emitters and we intentionally ignore any emitter errors.
	_ = ampel.publisher.PublishResults(ctx, results) //nolint:errcheck // best-effort publish

	return results, nil
}

// verify dispatches the verification to the right routine depending on the kind
// of policy material supplied and returns the assembled results.
func (ampel *Ampel) verify(
	ctx context.Context, opts *VerificationOptions, policy any, subject attestation.Subject,
) (papi.Results, error) {
	switch v := policy.(type) {
	case *papi.Policy:
		if len(opts.Policies) > 0 && !slices.Contains(opts.Policies, v.Id) {
			return &papi.ResultSet{Subject: subjectDescriptor(subject)}, nil
		}
		res, err := ampel.VerifySubjectWithPolicy(ctx, opts, v, subject)
		if err != nil {
			return nil, err
		}
		return res, nil
	case *papi.PolicySet:
		rs, err := ampel.VerifySubjectWithPolicySet(ctx, opts, v, subject)
		if err != nil {
			return nil, fmt.Errorf("evaluating policy set: %w", err)
		}
		return rs, nil
	case *papi.PolicyGroup:
		rs, err := ampel.VerifySubjectWithPolicyGroup(ctx, opts, v, subject)
		if err != nil {
			return nil, fmt.Errorf("evaluating policy group: %w", err)
		}
		return rs, nil
	case []*papi.PolicySet:
		return ampel.verifyPolicySets(ctx, opts, v, subject)
	default:
		return nil, fmt.Errorf("did not get a policy or policy set")
	}
}

// verifyPolicySets verifies a subject against several policy sets. Each set
// goes through the policy set path, so its common context values, keys and
// signer identities apply to its policies, and the results are merged: the
// subject passes when every set passes. A single set returns its own result
// set unchanged.
func (ampel *Ampel) verifyPolicySets(
	ctx context.Context, opts *VerificationOptions, sets []*papi.PolicySet, subject attestation.Subject,
) (*papi.ResultSet, error) {
	merged := &papi.ResultSet{
		Subject:   subjectDescriptor(subject),
		DateStart: timestamppb.Now(),
	}
	for i, set := range sets {
		set = selectPolicies(set, opts.Policies)
		rs, err := ampel.VerifySubjectWithPolicySet(ctx, opts, set, subject)
		if err != nil {
			return nil, fmt.Errorf("evaluating policy set #%d (%s): %w", i, set.GetId(), err)
		}
		if len(sets) == 1 {
			return rs, nil
		}
		merged.Results = append(merged.Results, rs.GetResults()...)
		merged.Groups = append(merged.Groups, rs.GetGroups()...)
	}
	// The merged status follows the same rules as a single set: any
	// failure fails it, all members skipped skips it, otherwise it passes.
	if err := merged.Assert(); err != nil {
		return nil, fmt.Errorf("asserting merged result set: %w", err)
	}
	return merged, nil
}

// selectPolicies returns the set with only the policies whose ids are listed,
// as a copy that keeps the set's common block. An empty list selects every
// policy and returns the set itself.
func selectPolicies(set *papi.PolicySet, ids []string) *papi.PolicySet {
	if len(ids) == 0 {
		return set
	}
	selected, ok := proto.Clone(set).(*papi.PolicySet)
	if !ok {
		return set
	}
	selected.Policies = slices.DeleteFunc(selected.Policies, func(p *papi.Policy) bool {
		return !slices.Contains(ids, p.GetId())
	})
	return selected
}

// subjectDescriptor returns the resource descriptor recording subject as
// the subject under evaluation in a result set.
func subjectDescriptor(subject attestation.Subject) *gointoto.ResourceDescriptor {
	return &gointoto.ResourceDescriptor{
		Name:   subject.GetName(),
		Uri:    subject.GetUri(),
		Digest: subject.GetDigest(),
	}
}

// VerifySubjectWithPolicySet runs a subject through a policy set.
func (ampel *Ampel) VerifySubjectWithPolicySet(
	ctx context.Context, originalOptions *VerificationOptions, policySet *papi.PolicySet, subject attestation.Subject,
) (*papi.ResultSet, error) {
	// Copy the options as we will mutate them after parsing the initial
	// attestations set.
	opts := *originalOptions

	// Now that we have a clone of the options, parse and add the
	// policySet's keys to the options set to reuse in the policies
	keys, err := policySet.PublicKeys()
	if err != nil {
		return nil, fmt.Errorf("reading PolicySet keys: %w", err)
	}
	opts.Keys = append(opts.Keys, keys...)

	// This is the resultSet to be returned
	resultSet := &papi.ResultSet{
		PolicySet: &papi.PolicyRef{
			Id:      policySet.GetId(),
			Version: policySet.GetMeta().GetVersion(),
			// Identity: &papi.Identity{},
			// Location: &gointoto.ResourceDescriptor{},
		},
		Meta:      policySet.GetMeta(),
		DateStart: timestamppb.Now(),
		Subject:   subjectDescriptor(subject),
	}

	// Check if the policy is viable before
	if err := ampel.impl.CheckPolicySet(ctx, &opts, policySet); err != nil {
		// If the policy failed validation, don't err. Fail the policy
		perr := PolicyError{}
		if errors.As(err, &perr) {
			return failPolicySetWithError(resultSet, perr), nil
		}
		// ..else something broke
		return nil, fmt.Errorf("checking policy: %w", err)
	}

	// Build the required evaluators
	evaluators := map[class.Class]evaluator.Evaluator{}
	// TODO(puerco): We should BuildEvaluators to get the already built evaluators
	for _, p := range policySet.Policies {
		policyEvals, err := ampel.impl.BuildEvaluators(&opts, p)
		if err != nil {
			return nil, fmt.Errorf("building evaluators: %w", err)
		}
		maps.Insert(evaluators, maps.All(policyEvals))
	}
	for _, g := range policySet.GetGroups() {
		groupEvals, err := ampel.impl.BuildGroupEvaluators(&opts, g)
		if err != nil {
			return nil, fmt.Errorf("building group evaluators: %w", err)
		}
		maps.Insert(evaluators, maps.All(groupEvals))
	}

	// Parse any extra attestation files defined in the options
	atts, err := ampel.impl.ParseAttestations(ctx, &opts, subject)
	if err != nil {
		return nil, fmt.Errorf("parsing single attestations: %w", err)
	}
	ctx = withExplicitEvidence(ctx, atts)

	// Mutate the options set to avoid reparsing the paths
	opts.AttestationFiles = []string{}
	opts.Attestations = atts

	// Load the policyset eval ctx definition into the go contect
	ctx, evalContext := ampel.loadElementEvalContextDef(ctx, policySet)

	// Publish the subject on the evalcontext so context-value expressions and
	// the evaluator runtimes can reach it via ctx.
	evalContext.Subject = subject
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	// Here we build the context that will be common for all policies as defined
	// in the policy set.
	evalContextValues, err := ampel.impl.AssembleEvalContextValues(ctx, &opts, evaluators, policySet.GetCommon().GetContext())
	if err != nil {
		return nil, fmt.Errorf("assembling policy context: %w", err)
	}

	// Now  that we have the computed context, populate the resultset common context
	// with the computed values. The common context is guaranteed to have an entry
	// matching the definition un the policySet common, even if nil.
	commonContext := map[string]any{}
	for contextValName := range policySet.GetCommon().GetContext() {
		if v, ok := evalContextValues[contextValName]; ok {
			commonContext[contextValName] = v
		} else {
			commonContext[contextValName] = nil
		}
	}

	if len(commonContext) > 0 {
		spb, err := structpb.NewStruct(commonContext)
		if err != nil {
			return nil, fmt.Errorf("building computed common context proto: %w", err)
		}
		resultSet.Common = &papi.ResultSetCommon{
			Context: spb,
		}
	}

	// Process policySet chain
	subjects, chain, policyFail, err := ampel.impl.ProcessPolicySetChainedSubjects(
		ctx, &opts, evaluators, ampel.Collector, policySet, evalContextValues, subject, atts,
	)
	if err != nil {
		// If policyFail is true, then we don't return an error but rather
		// a policy fail result based on the error
		if policyFail {
			return failPolicySetWithError(resultSet, err), nil
		}
		return nil, fmt.Errorf("processing chained subject: %w", err)
	}

	evalContext.ChainedSubjects = chain

	// Rebuild the go context as we are now shipping the chained subjects.
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	// If the chain returned no subjects, then we return an error unless
	// the verifier was explicitly set to allow empty chains.
	if len(policySet.GetChain()) > 0 && len(subjects) == 0 {
		if !opts.AllowEmptySetChains {
			return nil, fmt.Errorf("unable to complete evidence chain, no subject returned from selectors")
		}
		return softPassPolicySet(ctx, policySet, resultSet)
	}

	// The policies and groups below are evaluated concurrently but share the
	// attestation envelopes parsed once above and the collector agent. Publish a
	// lock on the context so the evidence-gathering steps (GatherAttestations'
	// key distribution and CheckIdentities' signature verification) can serialize
	// their mutation of that shared state for this run (see issue #298 and
	// sharedEvidenceLock).
	ctx = context.WithValue(ctx, sharedEvidenceLockKey{}, &sync.Mutex{})

	var mtx sync.Mutex
	t := throttler.New(int(opts.ParallelWorkers), len(policySet.Policies)*len(subjects))

	// Prealocate the results array to ensure the results are ordered
	allResults := make([]*papi.Result, len(policySet.GetPolicies())*len(subjects))

	// Now cycle each subject and evaluate....
	resCounter := 0
	for _, subsubject := range subjects {
		for i, pcy := range policySet.GetPolicies() {
			// ... and evaluate against each policy in the set
			go func(policy *papi.Policy, subject attestation.Subject, policyIndex, c int) {
				res, err := ampel.VerifySubjectWithPolicy(ctx, &opts, policy, subject)
				if err != nil {
					t.Done(fmt.Errorf("evaluating policy #%d: %w", policyIndex, err))
					return
				}

				if res == nil {
					t.Done(fmt.Errorf("eval of policy #%d returned nil", i))
					return
				}
				mtx.Lock()
				allResults[c] = res
				mtx.Unlock()
				t.Done(nil)
			}(pcy, subsubject, i, resCounter)

			// Return en the first eval error
			if numErrs := t.Throttle(); numErrs != 0 {
				return nil, fmt.Errorf("errors during evaluation: %w", t.Err())
			}
			resCounter++
		}
	}

	resultSet.Results = allResults

	// Evaluate any groups in the policy set
	allGroups := make([]*papi.ResultGroup, len(policySet.GetGroups())*len(subjects))
	groupCounter := 0
	gt := throttler.New(int(opts.ParallelWorkers), len(policySet.GetGroups())*len(subjects))
	for _, subsubject := range subjects {
		for i, grp := range policySet.GetGroups() {
			go func(group *papi.PolicyGroup, subject attestation.Subject, groupIndex, c int) {
				res, err := ampel.VerifySubjectWithPolicyGroup(ctx, &opts, group, subject)
				if err != nil {
					gt.Done(fmt.Errorf("evaluating group #%d: %w", groupIndex, err))
					return
				}

				if res == nil {
					gt.Done(fmt.Errorf("eval of group #%d returned nil", groupIndex))
					return
				}
				mtx.Lock()
				allGroups[c] = res
				mtx.Unlock()
				gt.Done(nil)
			}(grp, subsubject, i, groupCounter)

			if numErrs := gt.Throttle(); numErrs != 0 {
				return nil, fmt.Errorf("errors during group evaluation: %w", gt.Err())
			}
			groupCounter++
		}
	}
	resultSet.Groups = allGroups

	resultSet.DateEnd = timestamppb.Now()

	// Assert the policy set
	if err := resultSet.Assert(); err != nil {
		return nil, fmt.Errorf("asserting ResultSet: %w", err)
	}

	// Succcess!
	return resultSet, nil
}

// VerifySubjectWithPolicy verifies a subject against a single policy
func (ampel *Ampel) VerifySubjectWithPolicy(
	ctx context.Context, opts *VerificationOptions, policy *papi.Policy, originalSubject attestation.Subject,
) (*papi.Result, error) {
	// The subject may be replaced by the chain and the transformers below
	// but the result always records the original subject under evaluation.
	subject := originalSubject

	// Check if the policy is viable before
	if err := ampel.impl.CheckPolicy(ctx, opts, policy); err != nil {
		// If the policy failed validation, don't err. Fail the policy
		perr := PolicyError{}
		if errors.As(err, &perr) {
			return failPolicyWithError(policy, nil, originalSubject, perr), nil
		}
		// ..else something broke
		return nil, fmt.Errorf("checking policy: %w", err)
	}

	// Build the required evaluators
	evaluators, err := ampel.impl.BuildEvaluators(opts, policy)
	if err != nil {
		return nil, fmt.Errorf("building evaluators: %w", err)
	}

	// Parse any extra attestation files defined in the options
	atts, err := ampel.impl.ParseAttestations(ctx, opts, subject)
	if err != nil {
		return nil, fmt.Errorf("parsing single attestations: %w", err)
	}
	ctx = withExplicitEvidence(ctx, atts)

	// Publish the subject on the evalcontext so context-value expressions and
	// the evaluator runtimes can reach it via ctx.
	ec, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if !ok {
		ec = evalcontext.EvaluationContext{}
	}
	ec.Subject = subject
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, ec)

	evalContext, err := ampel.impl.AssembleEvalContextValues(ctx, opts, evaluators, policy.GetContext())
	if err != nil {
		return nil, fmt.Errorf("assembling policy context: %w", err)
	}

	// Check if the policy applies to this subject before fetching any
	// evidence. A policy whose condition is false is skipped.
	applies, err := ampel.evaluateWhen(ctx, opts, evaluators, policy.GetWhen(), policy.GetMeta().GetRuntime(), evalContext)
	if err != nil {
		return nil, fmt.Errorf("evaluating policy %q condition: %w", policy.GetId(), err)
	}
	if !applies {
		return skipPolicy(policy, originalSubject), nil
	}

	// Process chained subjects. These have access to all the read attestations
	// even when some will be discarded in the next step. Computing the chain
	// will use the configured repositories if more attestations are required.
	var chain []*papi.ChainedSubject
	subject, chain, policyFail, err := ampel.impl.ProcessChainedSubjects(
		ctx, opts, evaluators, ampel.Collector, policy, evalContext, subject, atts,
	)
	if err != nil {
		// If policyFail is true, then we don't return an error but rather
		// a policy fail result based on the error
		if policyFail {
			return failPolicyWithError(policy, chain, originalSubject, err), nil
		}
		return nil, fmt.Errorf("processing chained subject: %w", err)
	}

	// Now that we have the right subject from the chain, gather all the
	// required attestations. Note that this will filter out any from the
	// command line that don't match the the new subject under test as
	// determined from the chain resolution.
	atts, err = ampel.impl.GatherAttestations(ctx, opts, ampel.Collector, policy, subject, atts)
	if err != nil {
		return nil, fmt.Errorf("gathering evidence: %w", err)
	}

	// Resolve any from_context identity bindings against the assembled context
	// before checking identities, so the resolved value lands inside the identity
	// (AND-ed) and fails closed on a missing value. Covers the policy's own
	// identities and the common identities inherited from the context.
	resolvedIdentities, err := resolvePolicyIdentities(policy.GetIdentities(), evalContext)
	if err != nil {
		return nil, fmt.Errorf("resolving policy identities: %w", err)
	}
	if len(ec.Identities) > 0 {
		ec.Identities, err = resolvePolicyIdentities(ec.Identities, evalContext)
		if err != nil {
			return nil, fmt.Errorf("resolving common identities: %w", err)
		}
		ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, ec)
	}

	// Check identities to see if the attestations can be admitted
	// TODO(puerco)
	// Option: Unsigned statements cause a:fail or b:ignore
	allow, ids, idErrors, err := ampel.impl.CheckIdentities(ctx, opts, resolvedIdentities, atts)
	if err != nil {
		return nil, fmt.Errorf("error validating signer identity: %w", err)
	}

	if !allow {
		reason := errors.Join(idErrors...)
		perr := PolicyError{error: errors.New("attestation identity validation failed")}
		if errors.Is(reason, ErrUnverifiedAttestations) {
			perr.error = ErrUnverifiedAttestations
		}
		if reason != nil {
			perr.Guidance = reason.Error()
		}
		return failPolicyWithError(policy, chain, originalSubject, perr), nil
	}

	// Filter attestations to those applicable to the subject
	preds, err := ampel.impl.FilterAttestations(opts, subject, atts, ids)
	if err != nil {
		return nil, fmt.Errorf("filtering attestations: %w", err)
	}

	// Skip the policy when none of the admitted predicates match any of the
	// predicate types declared by the policy or its tenets.
	if policyPredicateMismatch(policy, preds) {
		return skipPolicyPredicateMismatch(policy, originalSubject), nil
	}

	transformers, err := ampel.impl.BuildTransformers(opts, policy)
	if err != nil {
		return nil, fmt.Errorf("building policy transformers: %w", err)
	}

	// Apply the defined tranformations to the subject and predicates
	subject, preds, err = ampel.impl.Transform(opts, transformers, policy, subject, preds)
	if err != nil {
		return nil, fmt.Errorf("applying transformations: %w", err)
	}

	// Evaluate the Policy
	result, err := ampel.impl.VerifySubject(ctx, opts, evaluators, policy, evalContext, subject, preds)
	if err != nil {
		return nil, fmt.Errorf("verifying subject: %w", err)
	}

	result.Chain = chain
	result.Subject = subjectDescriptor(originalSubject)

	// Assert the status from the evaluation results
	if err := ampel.impl.AssertResult(policy, result); err != nil {
		return nil, fmt.Errorf("asserting results: %w", err)
	}

	// Generate outputs
	return result, nil
}

// VerifySubjectWithPolicyGroup evaluates a policy group and its blocks
func (ampel *Ampel) VerifySubjectWithPolicyGroup(
	ctx context.Context, oOpts *VerificationOptions, group *papi.PolicyGroup, originalSubject attestation.Subject,
) (*papi.ResultGroup, error) {
	// The subject may be replaced by the chain below but the result always
	// records the original subject under evaluation.
	subject := originalSubject

	// DeepCopy the options as we will mutate them after parsing the initial
	// attestations set.
	opts := *oOpts

	// Now that we have a clone of the options, parse and add the
	// policySet's keys to the options set to reuse in the policies
	keys, err := group.PublicKeys()
	if err != nil {
		return nil, fmt.Errorf("reading PolicySet keys: %w", err)
	}
	opts.Keys = append(opts.Keys, keys...)

	// Resuktset to return
	res := &papi.ResultGroup{
		Subject:   subjectDescriptor(originalSubject),
		Status:    papi.StatusPASS,
		DateStart: timestamppb.Now(),
		DateEnd:   timestamppb.Now(),
		Group: &papi.PolicyGroupRef{
			Id:      group.GetId(),
			Version: group.GetMeta().GetVersion(),
			// Identity: &papi.Identity{},
			Location: group.GetSource().GetLocation(),
		},
		EvalResults: []*papi.BlockEvalResult{},
		Meta:        group.GetMeta(),
		Context:     &structpb.Struct{},
		Chain:       []*papi.ChainedSubject{},
		Common: &papi.ResultSetCommon{
			Context: &structpb.Struct{},
		},
	}

	// Check if the policy is viable before
	if err := ampel.impl.CheckPolicyGroup(ctx, &opts, group); err != nil {
		// If the policygroup failed validation, don't err. Fail the evaluation
		perr := PolicyError{}
		if errors.As(err, &perr) {
			return failPolicyGroupWithError(group, nil, originalSubject, err), nil
		}
		// else something broke
		return nil, fmt.Errorf("checking policy: %w", err)
	}

	// Build the required evaluators
	evaluators, err := ampel.impl.BuildGroupEvaluators(&opts, group)
	if err != nil {
		return nil, fmt.Errorf("building evaluators: %w", err)
	}

	// Parse any extra attestation files defined in the options
	atts, err := ampel.impl.ParseAttestations(ctx, &opts, subject)
	if err != nil {
		return nil, fmt.Errorf("parsing single attestations: %w", err)
	}
	ctx = withExplicitEvidence(ctx, atts)

	// Load the policyset eval ctx definition into the go contect
	ctx, evalContext := ampel.loadElementEvalContextDef(ctx, group)

	// Publish the subject on the evalcontext so context-value expressions and
	// the evaluator runtimes can reach it via ctx.
	evalContext.Subject = subject
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	// Here we build the context that will be common for all policies as defined
	// in the policy group.
	evalContextValues, err := ampel.impl.AssembleEvalContextValues(ctx, &opts, evaluators, group.GetCommon().GetContext())
	if err != nil {
		return nil, fmt.Errorf("assembling policy context: %w", err)
	}
	// Process chained subjects. These have access to all the read attestations
	// even when some will be discarded in the next step. Computing the chain
	// will use the configured repositories if more attestations are required.
	var chain []*papi.ChainedSubject

	subject, chain, policyFail, err := ampel.impl.ProcessChainedSubjects(
		ctx, &opts, evaluators, ampel.Collector, group, evalContextValues, subject, atts,
	)
	if err != nil {
		// If policyFail is true, then we don't return an error but rather
		// a policy fail result based on the error
		if policyFail {
			return failPolicyGroupWithError(group, chain, originalSubject, err), nil
		}
		return nil, fmt.Errorf("processing chained subject: %w", err)
	}

	res.Chain = chain
	evalContext.ChainedSubjects = chain

	// Rebuild the go context as we are now shipping the chained subjects.
	ctx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext)

	// Now  that we have the computed context, populate the resultset common context
	// with the computed values. The common context is guaranteed to have an entry
	// matching the definition un the policySet common, even if nil.
	commonContext := map[string]any{}
	for contextValName := range group.GetCommon().GetContext() {
		if v, ok := evalContextValues[contextValName]; ok {
			commonContext[contextValName] = v
		} else {
			commonContext[contextValName] = nil
		}
	}

	if len(commonContext) > 0 {
		spb, err := structpb.NewStruct(commonContext)
		if err != nil {
			return nil, fmt.Errorf("building computed common context proto: %w", err)
		}
		res.Common = &papi.ResultSetCommon{
			Context: spb,
		}
	}

	// Extract context values
	for i := range group.GetBlocks() {
		rs, err := ampel.verifySubjectWithBlock(ctx, &opts, evaluators, group, group.GetBlocks()[i], evalContextValues, subject)
		if err != nil {
			return nil, fmt.Errorf("verifying block: %w", err)
		}

		res.EvalResults = append(res.EvalResults, rs)
	}

	// A group whose blocks all skipped has nothing to assert on
	if allBlocksSkipped(res.EvalResults) {
		res.Status = papi.StatusSKIP
		res.DateEnd = timestamppb.Now()
		return res, nil
	}

	// Assert the group results based on the group's assert mode.
	// AND (default): all blocks must pass. OR: any block passing is sufficient.
	assertMode := group.GetMeta().GetAssertMode()
	if assertMode == assertModeOR {
		res.Status = papi.StatusFAIL
	}

	fails := []string{}
	for i := range res.EvalResults {
		if res.EvalResults[i].GetStatus() == papi.StatusFAIL && (assertMode == "" || assertMode == assertModeAND) {
			res.Status = papi.StatusFAIL
			if res.EvalResults[i].GetId() != "" {
				fails = append(fails, res.EvalResults[i].GetId())
			} else {
				fails = append(fails, fmt.Sprintf("#%d", i))
			}
		}

		if res.EvalResults[i].GetStatus() == papi.StatusPASS && assertMode == assertModeOR {
			res.Status = papi.StatusPASS
		}
	}
	if len(fails) > 0 && res.Status == papi.StatusFAIL {
		res.Error = fmt.Sprintf("Evaluation failed by blocks [%s]", strings.Join(fails, ", "))
	}

	// If the group has enforce OFF, downgrade FAIL to SOFTFAIL so the result
	// is informational rather than blocking.
	if res.Status == papi.StatusFAIL && group.GetMeta().GetEnforce() == enforceOFF {
		res.Status = papi.StatusSOFTFAIL
	}

	// Record the end of the group eval
	res.DateEnd = timestamppb.Now()
	return res, nil
}

func (ampel *Ampel) verifySubjectWithBlock(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	group *papi.PolicyGroup, block *papi.PolicyBlock, contextValues map[string]any, subject attestation.Subject,
) (*papi.BlockEvalResult, error) {
	rset := &papi.BlockEvalResult{
		Status:  papi.StatusPASS,
		Meta:    block.GetMeta(),
		Id:      block.GetId(),
		Results: []*papi.Result{},
		Error:   &papi.Error{},
	}

	// Check if the block applies before evaluating any of its policies
	applies, err := ampel.evaluateWhen(ctx, opts, evaluators, block.GetWhen(), group.GetMeta().GetRuntime(), contextValues)
	if err != nil {
		return nil, fmt.Errorf("evaluating block %q condition: %w", block.GetId(), err)
	}
	if !applies {
		rset.Status = papi.StatusSKIP
		rset.Error = &papi.Error{Message: skipMessage(block.GetWhen())}
		return rset, nil
	}

	if block.GetMeta().GetAssertMode() == assertModeOR {
		rset.Status = papi.StatusFAIL
	}

	// Evaluate the block's policies
	// TODO(puerco): Parallelize this thing
	for i := range block.GetPolicies() {
		res, err := ampel.VerifySubjectWithPolicy(ctx, opts, block.GetPolicies()[i], subject)
		if err != nil {
			return nil, fmt.Errorf("verifying policy #%d: %w", i, err)
		}
		rset.Results = append(rset.Results, res)

		if res.GetStatus() == papi.StatusFAIL && (block.GetMeta().GetAssertMode() == "" || block.GetMeta().GetAssertMode() == assertModeAND) {
			rset.Status = papi.StatusFAIL
			if opts.LazyBlockEval {
				break
			}
		}

		if res.GetStatus() == papi.StatusPASS && block.GetMeta().GetAssertMode() == assertModeOR {
			rset.Status = papi.StatusPASS
			if opts.LazyBlockEval {
				break
			}
		}
	}

	// A block whose policies all skipped has nothing to assert on
	if allPoliciesSkipped(rset.Results) {
		rset.Status = papi.StatusSKIP
		return rset, nil
	}

	// Populate the block error from failed policy results
	if rset.Status != papi.StatusPASS {
		assertMode := block.GetMeta().GetAssertMode()
		switch assertMode {
		case assertModeOR:
			// Copy the error from the last failed policy
			for i := len(rset.Results) - 1; i >= 0; i-- {
				if rset.Results[i].GetStatus() == papi.StatusFAIL {
					for _, er := range rset.Results[i].GetEvalResults() {
						if er.GetError() != nil && er.GetError().GetMessage() != "" {
							rset.Error = &papi.Error{
								Message:  er.GetError().GetMessage(),
								Guidance: er.GetError().GetGuidance(),
							}
							break
						}
					}
					break
				}
			}
		default: // AND or empty (default AND behavior)
			msgs := []string{}
			seen := map[string]struct{}{}
			for _, res := range rset.Results {
				if res.GetStatus() != papi.StatusFAIL {
					continue
				}
				for _, er := range res.GetEvalResults() {
					if er.GetError() != nil && er.GetError().GetMessage() != "" {
						msg := er.GetError().GetMessage()
						if _, ok := seen[msg]; !ok {
							seen[msg] = struct{}{}
							msgs = append(msgs, msg)
						}
					}
				}
			}
			if len(msgs) > 0 {
				rset.Error = &papi.Error{
					Message: strings.Join(msgs, "\n"),
				}
			}
		}
	}

	return rset, nil
}

// subjectToString builds a string to make a subject more human-readable
func subjectToString(subject attestation.Subject) string {
	vals := []string{}
	for algo, val := range subject.GetDigest() {
		if len(val) < 7 {
			continue
		}
		vals = append(vals, fmt.Sprintf("%s:%s", algo, val[0:6]))
	}
	var str string

	if subject.GetName() != "" {
		str = subject.GetName() + " "
	} else if subject.GetUri() != "" {
		str = subject.GetUri() + " "
	}

	if len(vals) > 0 {
		str += fmt.Sprintf("%+v", vals)
	}
	return str
}

// AttestResult writes an attestation capturing an evaluation result.
func (ampel *Ampel) AttestResult(w io.Writer, result *papi.Result) error {
	return attest.New().AttestTo(w, result)
}

// AttestResults writes an attestation capturing one or more
// evaluation results. Result and ResultGroup inputs are wrapped into
// a single-entry ResultSet by the attester so every output shape is
// consistent.
func (ampel *Ampel) AttestResults(w io.Writer, results papi.Results) error {
	return attest.New().AttestTo(w, results)
}

// evaluateWhen resolves a `when` condition and reports if the element it
// gates applies to the subject. The expression runs before any evidence is
// fetched: it sees the subject, the context values in scope and the runtime
// plugins, but no predicates. It runs in the runtime the condition names,
// else the runtime of the element, else the default. A condition that is not
// set always applies. An expression that fails or does not yield a boolean is
// an error, not a skip.
func (ampel *Ampel) evaluateWhen(
	ctx context.Context, opts *VerificationOptions, evaluators map[class.Class]evaluator.Evaluator,
	when *papi.When, runtime string, contextValues map[string]any,
) (bool, error) {
	if !when.IsSet() {
		return true, nil
	}

	cls := classForRuntime(when.GetRuntime())
	if cls == "" {
		cls = classForRuntime(runtime)
	}
	if cls == "" {
		cls = defaultEvaluatorClass
	}
	ev, ok := evaluators[cls]
	if !ok {
		return false, fmt.Errorf("runtime %q not available", cls)
	}

	exprCtx := ctx
	if ec, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext); ok {
		ec.ContextValues = maps.Clone(contextValues)
		exprCtx = context.WithValue(ctx, evalcontext.EvaluationContextKey{}, ec)
	}

	out, err := ev.EvalExpression(exprCtx, &opts.EvaluatorOptions, when.GetExpression())
	if err != nil {
		return false, fmt.Errorf("evaluating %q: %w", when.GetExpression(), err)
	}
	applies, ok := out.(bool)
	if !ok {
		return false, fmt.Errorf("condition %q must yield a boolean, got %T", when.GetExpression(), out)
	}
	return applies, nil
}

// skipMessage explains why an element was skipped.
func skipMessage(when *papi.When) string {
	return fmt.Sprintf("Skipped: condition %q is false", when.GetExpression())
}

// skipPolicy returns the result of a policy whose `when` condition is false.
// The condition is recorded as its single evaluation result so the results
// attestation explains the skip.
func skipPolicy(p *papi.Policy, subject attestation.Subject) *papi.Result {
	now := timestamppb.Now()
	return &papi.Result{
		Status:    papi.StatusSKIP,
		DateStart: now,
		DateEnd:   now,
		Policy: &papi.PolicyRef{
			Id:      p.GetId(),
			Version: p.GetMeta().GetVersion(),
		},
		Meta:    p.GetMeta(),
		Subject: subjectDescriptor(subject),
		EvalResults: []*papi.EvalResult{{
			Id:         "when",
			Status:     papi.StatusSKIP,
			Date:       now,
			Assessment: &papi.Assessment{Message: skipMessage(p.GetWhen())},
		}},
	}
}

// skipPolicyPredicateMismatch returns a SKIP result for a policy whose declared
// predicate types do not match any of the available attestation predicates. It
// is modeled on skipPolicy but uses a predicate-mismatch-specific message
// instead of referencing the when condition.
func skipPolicyPredicateMismatch(p *papi.Policy, subject attestation.Subject) *papi.Result {
	now := timestamppb.Now()
	return &papi.Result{
		Status:    papi.StatusSKIP,
		DateStart: now,
		DateEnd:   now,
		Policy: &papi.PolicyRef{
			Id:      p.GetId(),
			Version: p.GetMeta().GetVersion(),
		},
		Meta:    p.GetMeta(),
		Subject: subjectDescriptor(subject),
		EvalResults: []*papi.EvalResult{{
			Id:     "predicate-match",
			Status: papi.StatusSKIP,
			Date:   now,
			Assessment: &papi.Assessment{
				Message: "no attestations match the policy's declared predicate types",
			},
		}},
	}
}

// policyPredicateMismatch returns true when the policy declares at least one
// predicate type (at the policy level or in any tenet) but none of the
// available predicates match any of those declared types. A policy with no
// declared types is unconstrained and never matches.
func policyPredicateMismatch(p *papi.Policy, preds []attestation.Predicate) bool {
	// Collect all declared predicate types from the policy and its tenets.
	declared := map[attestation.PredicateType]struct{}{}
	for _, t := range p.GetPredicates().GetTypes() {
		declared[attestation.PredicateType(t)] = struct{}{}
	}
	for _, tenet := range p.GetTenets() {
		for _, t := range tenet.GetPredicates().GetTypes() {
			declared[attestation.PredicateType(t)] = struct{}{}
		}
	}

	// No declared types means unconstrained — never skip.
	if len(declared) == 0 {
		return false
	}

	// Check if any available predicate matches a declared type.
	for _, pred := range preds {
		if _, ok := declared[pred.GetType()]; ok {
			return false
		}
	}
	return true
}

// allPoliciesSkipped reports if there are results and every one is a skip.
func allPoliciesSkipped(results []*papi.Result) bool {
	for _, r := range results {
		if r.GetStatus() != papi.StatusSKIP {
			return false
		}
	}
	return len(results) > 0
}

// allBlocksSkipped reports if there are block results and every one is a skip.
func allBlocksSkipped(results []*papi.BlockEvalResult) bool {
	for _, r := range results {
		if r.GetStatus() != papi.StatusSKIP {
			return false
		}
	}
	return len(results) > 0
}

// failPolicySetWithError completes a policy set and sets the specified error
func failPolicySetWithError(set *papi.ResultSet, err error) *papi.ResultSet {
	guidance := ""
	//nolint:errorlint
	if pe, ok := err.(PolicyError); ok {
		guidance = pe.Guidance
	}

	set.Error = &papi.Error{
		Message:  err.Error(),
		Guidance: guidance,
	}

	set.DateEnd = timestamppb.Now()
	return set
}

// failPolicyWithError returns a failed status result for the policicy where all
// tennets are failed with error err. If err is a `PolicyError` then the result
// error guidance for the tenets will be read from it.
func failPolicyWithError(p *papi.Policy, chain []*papi.ChainedSubject, subject attestation.Subject, err error) *papi.Result {
	if subject == nil {
		subject = &gointoto.ResourceDescriptor{}
	}
	res := &papi.Result{
		Status:    papi.StatusFAIL,
		DateStart: timestamppb.Now(),
		DateEnd:   timestamppb.Now(),
		Policy: &papi.PolicyRef{
			Id:      p.Id,
			Version: p.GetMeta().GetVersion(),
		},
		EvalResults: []*papi.EvalResult{},
		Meta:        p.GetMeta(),
		Chain:       chain,
		Subject: &gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		},
	}

	guidance := ""
	//nolint:errorlint
	if pe, ok := err.(PolicyError); ok {
		guidance = pe.Guidance
	}
	for _, t := range p.Tenets {
		er := &papi.EvalResult{
			Id:         t.Id,
			Status:     papi.StatusFAIL,
			Date:       timestamppb.Now(),
			Output:     nil,
			Statements: nil, // Or do we define it?
			Error: &papi.Error{
				Message:  err.Error(),
				Guidance: guidance,
			},
			Assessment: nil,
		}
		res.EvalResults = append(res.EvalResults, er)
	}
	return res
}

// failPolicyGroupWithError returns a failed status result for the policyGroup
func failPolicyGroupWithError(p *papi.PolicyGroup, chain []*papi.ChainedSubject, subject attestation.Subject, err error) *papi.ResultGroup {
	if subject == nil {
		subject = &gointoto.ResourceDescriptor{}
	}
	res := &papi.ResultGroup{
		Status:    papi.StatusFAIL,
		DateStart: timestamppb.Now(),
		DateEnd:   timestamppb.Now(),
		Group: &papi.PolicyGroupRef{
			Id:      p.Id,
			Version: p.GetMeta().GetVersion(),
		},
		// TODO
		EvalResults: []*papi.BlockEvalResult{},
		Meta:        p.GetMeta(),
		Chain:       chain,
		Subject: &gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		},
		Error: err.Error(),
	}

	return res
}

// loadElementEvalContextDef adds the evaluation context definition from the element
// into the Go context (many context, I know :P)  If there is already an eval context
// in the go context, we add the new definitions from the policy material element.
//
// Returns the new go context loaded with the augmented eval ctx definition and the
// new evaluation context.
func (ampel *Ampel) loadElementEvalContextDef(ctx context.Context, element papi.CommonProvider) (context.Context, evalcontext.EvaluationContext) {
	// First, extract any existing evaluation context. The map and slice fields
	// inside EvaluationContext are reference types, so when this function runs
	// concurrently across goroutines sharing the same parent ctx we must clone
	// them before mutating to avoid concurrent map writes / slice races.
	parent, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	evalContext := evalcontext.EvaluationContext{
		Context:    map[string]*papi.ContextVal{},
		Identities: []*sapi.Identity{},
	}
	if ok {
		maps.Copy(evalContext.Context, parent.Context)
		evalContext.Identities = append(evalContext.Identities, parent.Identities...)
		evalContext.ContextValues = parent.ContextValues
		evalContext.Subject = parent.Subject
		evalContext.Policy = parent.Policy
		evalContext.ChainedSubjects = parent.ChainedSubjects
	}

	// If the policy material has an eval context definition, then parse it and add
	// it to the the Go context payload
	if element.GetCommon() != nil && element.GetCommon().GetContext() != nil {
		for key, val := range element.GetCommon().GetContext() {
			evalContext.Context[key] = val
		}
	}

	// Pass the policySet identities to the individual policy evaluations
	if element.GetCommon() != nil && element.GetCommon().GetIdentities() != nil {
		// TODO(puerco): Here we should check if the context already has the same
		// identity to avoid duplication
		evalContext.Identities = append(evalContext.Identities, element.GetCommon().GetIdentities()...)
	}

	return context.WithValue(ctx, evalcontext.EvaluationContextKey{}, evalContext), evalContext
}

func softPassPolicySet(ctx context.Context, policySet *papi.PolicySet, resultSet *papi.ResultSet) (*papi.ResultSet, error) {
	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if !ok {
		evalContext = evalcontext.EvaluationContext{}
	}

	structVals, err := structpb.NewStruct(evalContext.ContextValues)
	if err != nil {
		return nil, fmt.Errorf("structuring context data: %w", err)
	}

	resultSet.Error = &papi.Error{
		Message:  "unable to complete evidence chain",
		Guidance: "PolicySet selectors did not return any subjects when evaluated",
	}
	resultSet.Status = papi.StatusPASS
	resultSet.DateEnd = timestamppb.Now()
	for _, pcy := range policySet.Policies {
		resultSet.Results = append(resultSet.Results, &papi.Result{
			Status:    papi.StatusSOFTFAIL,
			DateStart: resultSet.GetDateStart(),
			DateEnd:   timestamppb.Now(),
			Policy: &papi.PolicyRef{
				Id:       pcy.GetId(),
				Version:  pcy.GetMeta().GetVersion(),
				Location: pcy.GetSource().GetLocation(),
			},
			EvalResults: []*papi.EvalResult{
				{
					Status: papi.StatusSOFTFAIL,
					Date:   timestamppb.Now(),
					Error: &papi.Error{
						Message:  "Policy not evaluated, chain is empty",
						Guidance: "The policySet selectors did not return any subjects to verify",
					},
				},
			},
			Meta:    pcy.GetMeta(),
			Context: structVals,
			Chain:   evalContext.ChainedSubjects,
		})
	}

	return resultSet, nil
}
