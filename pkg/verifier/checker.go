package verifier

import (
	"context"
	"fmt"

	"github.com/policylabs/attestation"

	"github.com/carabiner-dev/ampel/pkg/oscal"
)

type defaultStatusChecker struct{}

type StatusOptions struct {
	ResultFiles []string
}

type Status struct{}

// CheckStatus matches an artifacts requirements against an OSCAL catalog or profile
func (ampel *Ampel) CheckStatus(ctx context.Context, opts *StatusOptions, catalog *oscal.Catalog, subject attestation.Subject) (*Status, error) {
	envelopes, err := ampel.checker.GatherResults(ctx, opts, subject)
	if err != nil {
		return nil, fmt.Errorf("gathering evidence: %w", err)
	}

	auth, err := ampel.checker.CheckIdentities(opts, envelopes)
	if err != nil {
		return nil, fmt.Errorf("checking identities: %w", err)
	}
	if !auth {
		return nil, fmt.Errorf("unable to check compliance status: signature authorization failed")
	}

	results, err := ampel.checker.ParseAttestedResults(ctx, opts, envelopes)
	if err != nil {
		return nil, fmt.Errorf("parsing results: %w", err)
	}

	status, err := ampel.checker.ComputeComplianceStatus(catalog, results)
	if err != nil {
		return nil, fmt.Errorf("computing compliance status: %w", err)
	}

	// Done!
	return status, nil
}

// GatherResults reads results attestation from configured sources,
// parses them and returns the parsed envelopes
func (dsc *defaultStatusChecker) GatherResults(context.Context, *StatusOptions, attestation.Subject) ([]attestation.Envelope, error) {
	return nil, nil
}

// ParseAttestedResults extracts the predicates from the envelopes
func (dsc *defaultStatusChecker) ParseAttestedResults(context.Context, *StatusOptions, []attestation.Envelope) ([]attestation.Predicate, error) {
	return nil, nil
}

// CheckIdentities verifies the signatures from the attested results
func (dsc *defaultStatusChecker) CheckIdentities(*StatusOptions, []attestation.Envelope) (bool, error) {
	return false, nil
}

// ComputeComplianceStatus computes the compliance status and returns the
// status in a struct
func (dsc *defaultStatusChecker) ComputeComplianceStatus(*oscal.Catalog, []attestation.Predicate) (*Status, error) {
	return nil, nil
}
