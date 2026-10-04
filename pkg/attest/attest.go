// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package attest writes attestations capturing evaluation results in
// the format chosen by the caller. It is the home for the signing
// pipeline that will turn ampel results into signed attestations —
// for now it covers the format dispatch and intoto statement
// construction so call sites that move to it today don't change shape
// when signing lands.
package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/statement/intoto"
	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/carabiner-dev/predicates"
	"github.com/carabiner-dev/signer"
)

// ampelVerifierID is the verifier identifier embedded in every
// attestation produced by this package (VSA, SVR, and the ampel
// resultset format).
const ampelVerifierID = "https://carabiner.dev/ampel@v1"

// formatAmpel is the canonical name of the native ampel resultset
// attestation format.
const formatAmpel = "ampel"

// ResultsAttester writes a results attestation in the format chosen
// per call via WithFormat. The "ampel" format produces an in-toto
// statement carrying a predicates.ResultSet; "vsa" and "svr" route
// through their format-specific drivers.
//
// FnOpts passed to New populate the attester's defaults; the same
// FnOpts passed to AttestTo / AttestToFile override those defaults
// for one call. A typical CLI configures once via New (e.g. with a
// pre-built *signer.Signer) and never overrides; library callers
// can stay stateless and pass options per call instead.
type ResultsAttester struct {
	defaults attestOptions
}

// New returns a ResultsAttester with optional instance-level
// defaults. Pass FnOpts here when the same configuration applies to
// every call (typical CLI use); otherwise leave empty and pass
// options per call.
func New(opts ...FnOpt) *ResultsAttester {
	a := &ResultsAttester{defaults: defaultAttestOptions()}
	for _, fn := range opts {
		fn(&a.defaults)
	}
	return a
}

// FnOpt configures a ResultsAttester. Passed to New, it sets
// instance-wide defaults; passed to AttestTo / AttestToFile, it
// overrides those defaults for that one call.
type FnOpt func(*attestOptions)

// attestOptions is the resolved configuration for one Attest* call.
type attestOptions struct {
	format      string
	prettyPrint bool
	signer      *signer.Signer
}

// defaultAttestOptions returns the baseline config used when no
// FnOpts are supplied at construction or call time.
func defaultAttestOptions() attestOptions {
	return attestOptions{format: formatAmpel, prettyPrint: true}
}

// WithFormat selects the results-attestation format for the call.
// Must be one of verifier.ResultsAttestationFormats. Empty resolves
// to "ampel" at dispatch, so passing through an unset
// AttestFormat option is safe.
func WithFormat(format string) FnOpt {
	return func(o *attestOptions) {
		o.format = format
	}
}

// WithPrettyPrint controls JSON formatting of the unsigned
// attestation. The default is true (2-space indented output); pass
// false for a single-line compact form.
//
// When a signer is configured via WithSigner this option is a
// no-op — the produced *signer.SignedArtifact serializes with the
// formatting dictated by its kind (sigstore Bundle: compact;
// DSSE envelope: indented).
func WithPrettyPrint(enabled bool) FnOpt {
	return func(o *attestOptions) {
		o.prettyPrint = enabled
	}
}

// WithSigner configures the attester to sign the produced
// attestation instead of writing the raw in-toto Statement. The
// output shape becomes the *signer.SignedArtifact's canonical JSON
// form (sigstore Bundle for the sigstore/SPIFFE backends, DSSE
// envelope for the key backend).
//
// nil resets to the unsigned path — useful per-call to override an
// instance-level default set at New time.
func WithSigner(s *signer.Signer) FnOpt {
	return func(o *attestOptions) {
		o.signer = s
	}
}

// AttestToFile writes the results attestation for results to path,
// truncating any existing file. The file handle is closed before
// the call returns. Per-call FnOpts override any defaults set at
// New time.
func (a *ResultsAttester) AttestToFile(path string, results papi.Results, opts ...FnOpt) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("opening results attestation path: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort close on a write target; AttestTo's error wins
	return a.AttestTo(f, results, opts...)
}

// AttestTo writes the results attestation for results to w. The
// effective configuration is the attester's defaults overlaid with
// any per-call FnOpts. Splitting the writer- and path-based entry
// points keeps the dispatch testable without touching the filesystem.
func (a *ResultsAttester) AttestTo(w io.Writer, results papi.Results, opts ...FnOpt) error {
	o := a.defaults
	for _, fn := range opts {
		fn(&o)
	}
	switch o.format {
	case formatAmpel, "":
		return a.attestAmpel(w, results, o)
	case "vsa":
		return a.attestVSA(w, results, o)
	case "svr":
		return a.attestSVR(w, results, o)
	default:
		return fmt.Errorf("unknown attestation format %q", o.format)
	}
}

// writeStatement writes stmt to w in either its raw in-toto JSON
// form (when no signer is configured) or as a signer.SignedArtifact
// (sigstore Bundle or DSSE envelope, depending on the backend).
// All format-specific writers funnel through this method so the
// signing dispatch lives in exactly one place.
func (a *ResultsAttester) writeStatement(w io.Writer, stmt *intoto.Statement, o attestOptions) error {
	if o.signer == nil {
		return writeStatementJSON(w, stmt, o.prettyPrint)
	}
	data, err := json.Marshal(stmt)
	if err != nil {
		return fmt.Errorf("serializing statement for signing: %w", err)
	}
	artifact, err := o.signer.SignStatement(data)
	if err != nil {
		return fmt.Errorf("signing statement: %w", err)
	}
	if _, err := artifact.WriteTo(w); err != nil {
		return fmt.Errorf("writing signed artifact: %w", err)
	}
	return nil
}

// attestAmpel writes an "ampel"-format results attestation. Result
// and ResultGroup inputs are wrapped into a single-entry ResultSet
// before serialization so every output is the same shape.
func (a *ResultsAttester) attestAmpel(w io.Writer, results papi.Results, o attestOptions) error {
	switch r := results.(type) {
	case *papi.Result:
		rs := &papi.ResultSet{
			Subject:   r.Subject,
			Results:   []*papi.Result{r},
			DateStart: r.DateStart,
			DateEnd:   r.DateEnd,
		}
		if err := rs.Assert(); err != nil {
			return fmt.Errorf("asserting results set: %w", err)
		}
		return a.writeResultSet(w, rs, o)
	case *papi.ResultSet:
		return a.writeResultSet(w, r, o)
	case *papi.ResultGroup:
		rs := &papi.ResultSet{
			Subject:   r.Subject,
			Groups:    []*papi.ResultGroup{r},
			DateStart: r.DateStart,
			DateEnd:   r.DateEnd,
		}
		if err := rs.Assert(); err != nil {
			return fmt.Errorf("asserting results set: %w", err)
		}
		return a.writeResultSet(w, rs, o)
	default:
		return errors.New("results are not Result, ResultSet or ResultGroup")
	}
}

// writeStatementJSON serializes stmt to w in either 2-space indented
// or compact single-line JSON. Used by every format-specific writer
// so the WithPrettyPrint behavior stays consistent across ampel, VSA
// and SVR output.
func writeStatementJSON(w io.Writer, stmt *intoto.Statement, pretty bool) error {
	var (
		data []byte
		err  error
	)
	if pretty {
		data, err = json.MarshalIndent(stmt, "", "  ")
	} else {
		data, err = json.Marshal(stmt)
	}
	if err != nil {
		return fmt.Errorf("serializing statement: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing statement: %w", err)
	}
	return nil
}

// writeResultSet builds an in-toto statement carrying a
// predicates.ResultSet and writes it via a.writeStatement. The statement
// is about the subject the set was evaluated against, not about the
// subjects recorded in its results: chained evaluations look at other
// artifacts along the way, but the verdict is still about the original
// subject.
func (a *ResultsAttester) writeResultSet(w io.Writer, resultset *papi.ResultSet, o attestOptions) error {
	if resultset == nil {
		return errors.New("unable to attest results, set is nil")
	}
	if len(resultset.GetSubject().GetDigest()) == 0 {
		return errors.New("unable to attest results, the set has no subject with digests")
	}

	stmt := intoto.NewStatement()
	stmt.AddSubject(resultset.GetSubject())
	stmt.PredicateType = predicates.PredicateTypeResultSet
	stmt.Predicate = &predicates.ResultSet{Parsed: resultset}

	return a.writeStatement(w, stmt, o)
}

// stringifyDigests returns a canonical algo:value/algo:value... form
// of subject's digest map suitable for set-membership checks.
func stringifyDigests(subject attestation.Subject) string {
	digest := subject.GetDigest()
	s := make([]string, 0, len(digest))
	for algo, val := range digest {
		s = append(s, fmt.Sprintf("%s:%s", algo, val))
	}
	slices.Sort(s)
	return strings.Join(s, "/")
}
