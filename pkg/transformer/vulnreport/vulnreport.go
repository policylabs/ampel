// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package vulnreport implements a transformer that normalizes scanner reports
// (Trivy, Grype, OSV-Scanner) into the OSV results format, and optionally
// projects them onto the in-toto vulns/v0.2 predicate.
//
// The conversion logic lives in the carabiner-dev/osv library; this transformer
// is a thin adapter that routes each input predicate to the right converter and
// wraps the result as a predicate.
package vulnreport

import (
	"encoding/json"
	"fmt"

	"github.com/carabiner-dev/osv/go/osv"
	"github.com/carabiner-dev/osv/scanners/grype"
	"github.com/carabiner-dev/osv/scanners/trivy"
	"github.com/carabiner-dev/osv/vulns"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/predicate/generic"
	cosv "github.com/policylabs/collector/predicate/osv"
	ctrivy "github.com/policylabs/collector/predicate/trivy"
	cvulns "github.com/policylabs/collector/predicate/vulns"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// GrypePredicateType identifies a Grype JSON report. Grype does not define an
// official in-toto predicate type, so we adopt the tool's repository URL.
const GrypePredicateType = attestation.PredicateType("https://github.com/anchore/grype")

// legacyOSVPredicateType is the pre-@v1 OSV results type. The collector's osv
// parser normalizes it to cosv.PredicateType, but the transformer also accepts
// it directly for robustness.
const legacyOSVPredicateType = attestation.PredicateType("https://ossf.github.io/osv-schema/results@v1.6.7")

var ClassName = "vulnreport"

// PredicateTypes are the scanner report predicate types this transformer
// accepts as input.
var PredicateTypes = []attestation.PredicateType{
	ctrivy.PredicateType,
	cosv.PredicateType,
	legacyOSVPredicateType,
	GrypePredicateType,
}

// scannerURIs maps each accepted input type to the scanner identity recorded in
// the vulns/v0.2 predicate (the OSV format does not carry scanner identity).
var scannerURIs = map[attestation.PredicateType]string{
	ctrivy.PredicateType:   "https://trivy.dev",
	cosv.PredicateType:     "https://github.com/google/osv-scanner",
	legacyOSVPredicateType: "https://github.com/google/osv-scanner",
	GrypePredicateType:     "https://github.com/anchore/grype",
}

// Output formats the vulnreport transformer can emit.
const (
	OutputOSV        = "osv"
	OutputVulnReport = "vulnreport"
)

// Config is the user-facing configuration for the vulnreport transformer.
type Config struct {
	// Output selects the predicate format emitted by Mutate.
	// Defaults to "osv". "vulnreport" emits an in-toto vulns/v0.2 predicate.
	Output string `json:"output"`
}

func New() *Transformer {
	return &Transformer{}
}

// Transformer implements the normalizer from scanner reports to OSV / vulns.
type Transformer struct {
	config Config
}

// Init parses the policy-supplied config and applies defaults.
func (t *Transformer) Init(raw *structpb.Struct) error {
	t.config = Config{Output: OutputOSV}
	if raw == nil {
		return nil
	}
	data, err := protojson.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshaling config struct: %w", err)
	}
	if err := json.Unmarshal(data, &t.config); err != nil {
		return fmt.Errorf("decoding vulnreport config: %w", err)
	}
	if t.config.Output == "" {
		t.config.Output = OutputOSV
	}
	switch t.config.Output {
	case OutputOSV, OutputVulnReport:
	default:
		return fmt.Errorf("unsupported output %q (want %q or %q)", t.config.Output, OutputOSV, OutputVulnReport)
	}
	return nil
}

func (t *Transformer) Mutate(
	_ attestation.Subject, preds []attestation.Predicate,
) (attestation.Subject, []attestation.Predicate, error) {
	newPreds := []attestation.Predicate{}
	for _, original := range preds {
		results, ok, err := toOSVResults(original)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			// Not a scanner report we know how to normalize; skip it.
			continue
		}

		var (
			newPred attestation.Predicate
			perr    error
		)
		switch t.config.Output {
		case OutputVulnReport:
			newPred, perr = toVulnReportPredicate(results, original.GetType())
		default:
			newPred, perr = toOSVPredicate(results)
		}
		if perr != nil {
			return nil, nil, fmt.Errorf("building %s predicate: %w", t.config.Output, perr)
		}
		newPreds = append(newPreds, newPred)
	}
	return nil, newPreds, nil
}

// osvParser is used only for its dual-read SupportsType, so a predicate typed
// with either the current @v1 or the legacy @v1.6.7 OSV type is recognized even
// if it was not normalized upstream by the collector.
var osvParser = cosv.New()

// toOSVResults normalizes a scanner report predicate into the OSV results
// format. The bool is false when the predicate is not a supported scanner
// report, in which case it should be skipped.
func toOSVResults(pred attestation.Predicate) (*osv.Results, bool, error) {
	data := pred.GetData()
	switch {
	case pred.GetType() == ctrivy.PredicateType:
		report, err := trivy.Parse(data)
		if err != nil {
			return nil, true, fmt.Errorf("parsing trivy report: %w", err)
		}
		results, err := report.ToOSV()
		return results, true, err
	case pred.GetType() == GrypePredicateType:
		doc, err := grype.Parse(data)
		if err != nil {
			return nil, true, fmt.Errorf("parsing grype report: %w", err)
		}
		results, err := doc.ToOSV()
		return results, true, err
	case osvParser.SupportsType(pred.GetType()):
		// OSV-Scanner already emits OSV; parse it straight through.
		results, err := osv.NewParser().ParseResults(data)
		if err != nil {
			return nil, true, fmt.Errorf("parsing osv results: %w", err)
		}
		return results, true, nil
	default:
		return nil, false, nil
	}
}

// toOSVPredicate wraps an OSV results set as an OSV predicate.
func toOSVPredicate(results *osv.Results) (attestation.Predicate, error) {
	data, err := protojson.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("marshaling osv predicate: %w", err)
	}
	return &generic.Predicate{
		Type:   cosv.PredicateType,
		Parsed: results,
		Data:   data,
	}, nil
}

// toVulnReportPredicate projects an OSV results set onto a vulns/v0.2 predicate.
func toVulnReportPredicate(results *osv.Results, inputType attestation.PredicateType) (attestation.Predicate, error) {
	predicate, err := vulns.FromResults(results, scannerURIs[inputType])
	if err != nil {
		return nil, fmt.Errorf("projecting to vulns/v0.2: %w", err)
	}
	data, err := protojson.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("marshaling vulns/v0.2 predicate: %w", err)
	}
	return &generic.Predicate{
		Type:   cvulns.PredicateType,
		Parsed: predicate,
		Data:   data,
	}, nil
}
