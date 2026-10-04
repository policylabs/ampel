// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/predicate/generic"
	"github.com/carabiner-dev/collector/statement/intoto"
	papi "github.com/carabiner-dev/policy/api/v1"
	v1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// slsaVersion version used as base to compute the VSA
	slsaVersion = "1.1"

	// vsaContextResourceURIKey is the policy-context key recognized
	// for overriding the VSA resource URI.
	vsaContextResourceURIKey = "vsa.resourceUri"

	// statusPassed is the SLSA VerificationResult value for a passing
	// verification.
	statusPassed = "PASSED"
)

// attestVSA writes a VSA attestation for results.
//
// The VerificationResult on the VSA is mapped from the PolicySet
// assessment status, and the VerifiedLevels list is taken from the
// controls advertised by the policies; SLSA-track controls
// additionally set the VSA's slsaVersion. Dependency levels are
// computed by extracting the results of policies chained to a
// different subject — those policies are expected to have their own
// controls section, defining the level they check.
// ErrSkippedResult is returned when asked to attest a verification summary
// for a result whose policies did not apply to the subject. Nothing was
// verified, so there is no PASSED or FAILED to report.
var ErrSkippedResult = errors.New("skipped results cannot be attested: the policy did not apply to the subject")

func (a *ResultsAttester) attestVSA(w io.Writer, results papi.Results, o attestOptions) error {
	switch r := results.(type) {
	case *papi.Result:
		if r.GetStatus() == papi.StatusSKIP {
			return fmt.Errorf("policy %q: %w", r.GetPolicy().GetId(), ErrSkippedResult)
		}
		return a.writeVSAFromResult(w, r, o)
	case *papi.ResultSet:
		if r.GetStatus() == papi.StatusSKIP {
			return fmt.Errorf("policy set %q: %w", r.GetPolicySet().GetId(), ErrSkippedResult)
		}
		return a.writeVSAFromResultSet(w, r, o)
	case *papi.ResultGroup:
		return errors.New("rendering result groups as VSAs is not supported yet")
	default:
		return errors.New("unable to determine results type to attest")
	}
}

func (a *ResultsAttester) writeVSAFromResultSet(w io.Writer, set *papi.ResultSet, o attestOptions) error {
	vsaData := &v1.VerificationSummary{
		Verifier: &v1.VerificationSummary_Verifier{
			Id: ampelVerifierID,
		},
		TimeVerified: set.GetDateEnd(),
		// We set the resource URI here to the resource URI of the verified subject
		// but if the policyset common context defines one, we'll override it later.
		ResourceUri: set.GetSubject().GetUri(),
		Policy: &v1.VerificationSummary_Policy{
			Uri:    set.GetMeta().GetOrigin().GetUri(),
			Digest: set.GetMeta().GetOrigin().GetDigest(),
		},
		InputAttestations:  []*v1.VerificationSummary_InputAttestation{},
		VerificationResult: resultStringToSLSAResult(set.GetStatus()),
		VerifiedLevels:     []string{},
		DependencyLevels:   nil,
	}

	inputs := []attestation.Subject{}
	depLevels := map[string]uint64{}

	// Check if the policyset defined a resourceURI for the VSA and replace the
	// value we got from the subject resource locator.
	if setContext := set.GetCommon().GetContext(); setContext != nil {
		if s, ok := setContext.AsMap()[vsaContextResourceURIKey].(string); ok && s != "" {
			vsaData.ResourceUri = s
		}
	}

	var verifiedSomeSlsa bool
	for _, r := range set.Results {
		for _, er := range r.EvalResults {
			for _, stRef := range er.GetStatements() {
				if !subjectInList(inputs, stRef.GetAttestation()) {
					inputs = append(inputs, stRef.GetAttestation())
				}
			}
		}

		// Collect the levels advertised by passing policies.
		if r.GetStatus() != papi.StatusPASS {
			continue
		}
		for _, ctl := range r.GetMeta().GetControls() {
			if ctl.Id == "" {
				continue
			}
			label := strings.ReplaceAll(ctl.Label(), "-", "_")

			// Only SLSA-track controls set the VSA's slsaVersion; controls
			// from other frameworks still contribute their namespaced label.
			if strings.HasPrefix(label, "SLSA_") {
				verifiedSomeSlsa = true
			}

			// Add the level to the verified levels when the result subject
			// matches the policyset subject. Otherwise treat the policyset as
			// chained to verify dependencies.
			if attestation.SubjectsMatch(set.GetSubject(), r.GetSubject()) {
				if !slices.Contains(vsaData.VerifiedLevels, label) {
					vsaData.VerifiedLevels = append(vsaData.VerifiedLevels, label)
				}
			} else {
				depLevels[label]++
			}
		}
	}
	if len(depLevels) > 0 {
		vsaData.DependencyLevels = depLevels
	}

	vsaData.InputAttestations = subjectsToSummaryInputs(inputs)
	if verifiedSomeSlsa {
		vsaData.SlsaVersion = slsaVersion
	}
	return a.writeVSAStatement(w, set.GetSubject(), vsaData, o)
}

func (a *ResultsAttester) writeVSAFromResult(w io.Writer, result *papi.Result, o attestOptions) error {
	vsaData := &v1.VerificationSummary{
		Verifier: &v1.VerificationSummary_Verifier{
			Id: ampelVerifierID,
		},
		TimeVerified: result.GetDateEnd(),
		// We fix the resource URI here to the resource URI of the verification
		// subject, but if the policy context defines one, we'll override it.
		ResourceUri: result.GetSubject().GetUri(),
		Policy: &v1.VerificationSummary_Policy{
			Uri:    result.GetMeta().GetOrigin().GetUri(),
			Digest: result.GetMeta().GetOrigin().GetDigest(),
		},
		InputAttestations:  []*v1.VerificationSummary_InputAttestation{},
		VerificationResult: resultStringToSLSAResult(result.GetStatus()),
		VerifiedLevels:     []string{},
		DependencyLevels:   nil,
	}

	if resContext := result.GetContext(); resContext != nil {
		if v, ok := resContext.AsMap()[vsaContextResourceURIKey]; ok && v != nil {
			if s, ok2 := v.(string); ok2 && s != "" {
				vsaData.ResourceUri = s
			}
		}
	}

	var verifiedSomeSlsa bool
	for _, ctl := range result.GetMeta().GetControls() {
		if ctl.Id == "" {
			continue
		}
		label := strings.ReplaceAll(ctl.Label(), "-", "_")

		// Only SLSA-track controls set the VSA's slsaVersion; controls
		// from other frameworks still contribute their namespaced label.
		if strings.HasPrefix(label, "SLSA_") {
			verifiedSomeSlsa = true
		}
		vsaData.VerifiedLevels = append(vsaData.VerifiedLevels, label)
	}

	inputs := []attestation.Subject{}
	for _, er := range result.EvalResults {
		for _, stRef := range er.GetStatements() {
			if !subjectInList(inputs, stRef.GetAttestation()) {
				inputs = append(inputs, stRef.GetAttestation())
			}
		}
	}
	vsaData.InputAttestations = subjectsToSummaryInputs(inputs)
	if verifiedSomeSlsa {
		vsaData.SlsaVersion = slsaVersion
	}
	return a.writeVSAStatement(w, result.GetSubject(), vsaData, o)
}

// writeVSAStatement wraps the populated VSA predicate in an in-toto
// statement and routes it through a.writeStatement so signing and
// pretty-print dispatch stay centralized.
func (a *ResultsAttester) writeVSAStatement(w io.Writer, subject attestation.Subject, att *v1.VerificationSummary, o attestOptions) error {
	vsaJsonData, err := protojson.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshaling vsa: %w", err)
	}

	pred := &generic.Predicate{
		Type:   attestation.PredicateType("https://slsa.dev/verification_summary/v1"),
		Parsed: att,
		Data:   vsaJsonData,
	}

	statement := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(&gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		}),
	)

	return a.writeStatement(w, statement, o)
}

// resultStringToSLSAResult translates ampel evaluation status strings
// to the VerificationResult vocabulary used by SLSA.
func resultStringToSLSAResult(status string) string {
	switch status {
	case papi.StatusPASS, papi.StatusSOFTFAIL:
		return statusPassed
	case papi.StatusFAIL:
		return "FAILED"
	default:
		return ""
	}
}

func subjectsToSummaryInputs(inputs []attestation.Subject) []*v1.VerificationSummary_InputAttestation {
	if len(inputs) == 0 {
		return nil
	}
	ret := make([]*v1.VerificationSummary_InputAttestation, 0, len(inputs))
	for _, s := range inputs {
		ret = append(ret, &v1.VerificationSummary_InputAttestation{
			Uri:    s.GetUri(),
			Digest: s.GetDigest(),
		})
	}
	return ret
}

// subjectInList reports whether needle's digests match any subject in
// haystack. Used to deduplicate input-attestation lists.
func subjectInList(haystack []attestation.Subject, needle attestation.Subject) bool {
	for _, sut := range haystack {
		if attestation.SubjectsMatch(sut, needle) {
			return true
		}
	}
	return false
}
