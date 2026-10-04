// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	svrpred "github.com/in-toto/attestation/go/predicates/svr/v01"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/predicate/generic"
	"github.com/policylabs/collector/statement/intoto"
	papi "github.com/policylabs/policy/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

const svrPredicateType = "https://in-toto.io/attestation/svr/v0.1"

// attestSVR writes a Simple Verification Result attestation for results.
func (a *ResultsAttester) attestSVR(w io.Writer, results papi.Results, o attestOptions) error {
	switch r := results.(type) {
	case *papi.Result:
		if r.GetStatus() == papi.StatusSKIP {
			return fmt.Errorf("policy %q: %w", r.GetPolicy().GetId(), ErrSkippedResult)
		}
		return a.writeSVRFromResult(w, r, o)
	case *papi.ResultSet:
		if r.GetStatus() == papi.StatusSKIP {
			return fmt.Errorf("policy set %q: %w", r.GetPolicySet().GetId(), ErrSkippedResult)
		}
		return a.writeSVRFromResultSet(w, r, o)
	case *papi.ResultGroup:
		return errors.New("rendering result groups as SVRs is not supported yet")
	default:
		return errors.New("unable to determine results type to attest")
	}
}

func (a *ResultsAttester) writeSVRFromResultSet(w io.Writer, set *papi.ResultSet, o attestOptions) error {
	policyAny, err := svrPolicyResourceDescriptor(set.GetMeta().GetOrigin())
	if err != nil {
		return fmt.Errorf("wrapping policy descriptor: %w", err)
	}

	svrData := &svrpred.SimpleVerificationResult{
		Verifier: &svrpred.SimpleVerificationResult_Verifier{
			Id:     ampelVerifierID,
			Policy: policyAny,
		},
		TimeCreated: set.GetDateEnd(),
		Properties:  []string{},
	}

	for _, r := range set.Results {
		if r.GetStatus() != papi.StatusPASS {
			continue
		}
		for _, ctl := range r.GetMeta().GetControls() {
			if ctl.Id == "" {
				continue
			}
			label := strings.ReplaceAll(ctl.Label(), "-", "_")
			if !slices.Contains(svrData.Properties, label) {
				svrData.Properties = append(svrData.Properties, label)
			}
		}
	}

	return a.writeSVRStatement(w, set.GetSubject(), svrData, o)
}

func (a *ResultsAttester) writeSVRFromResult(w io.Writer, result *papi.Result, o attestOptions) error {
	policyAny, err := svrPolicyResourceDescriptor(result.GetMeta().GetOrigin())
	if err != nil {
		return fmt.Errorf("wrapping policy descriptor: %w", err)
	}

	svrData := &svrpred.SimpleVerificationResult{
		Verifier: &svrpred.SimpleVerificationResult_Verifier{
			Id:     ampelVerifierID,
			Policy: policyAny,
		},
		TimeCreated: result.GetDateEnd(),
		Properties:  []string{},
	}

	for _, ctl := range result.GetMeta().GetControls() {
		if ctl.Id == "" {
			continue
		}
		label := strings.ReplaceAll(ctl.Label(), "-", "_")
		if !slices.Contains(svrData.Properties, label) {
			svrData.Properties = append(svrData.Properties, label)
		}
	}

	return a.writeSVRStatement(w, result.GetSubject(), svrData, o)
}

// writeSVRStatement wraps the populated SVR predicate in an in-toto
// statement and routes it through a.writeStatement so signing and
// pretty-print dispatch stay centralized. The protojson Any wrapper
// injects an "@type" field into the policy block; strip it so the
// SVR output stays clean.
func (a *ResultsAttester) writeSVRStatement(w io.Writer, subject attestation.Subject, att *svrpred.SimpleVerificationResult, o attestOptions) error {
	svrJsonData, err := protojson.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshaling svr: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(svrJsonData, &raw); err != nil {
		return fmt.Errorf("unmarshaling svr json: %w", err)
	}
	if verifier, ok := raw["verifier"].(map[string]any); ok {
		if policy, ok := verifier["policy"].(map[string]any); ok {
			delete(policy, "@type")
		}
	}
	svrJsonData, err = json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("re-marshaling svr json: %w", err)
	}

	pred := &generic.Predicate{
		Type:   attestation.PredicateType(svrPredicateType),
		Parsed: att,
		Data:   svrJsonData,
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

func svrPolicyResourceDescriptor(origin attestation.Subject) (*anypb.Any, error) {
	rd := &gointoto.ResourceDescriptor{
		Uri:    origin.GetUri(),
		Digest: origin.GetDigest(),
	}
	return anypb.New(rd)
}
