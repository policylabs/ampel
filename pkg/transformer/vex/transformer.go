// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package vex is a transformer that reads in a vulnerability report
// and a number of VEX documents and suppresses those that do not affect
// the subject
package vex

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/predicate/generic"
	aosv "github.com/carabiner-dev/collector/predicate/osv"
	"github.com/carabiner-dev/hasher"
	"github.com/carabiner-dev/osv/go/osv"
	gointoto "github.com/in-toto/attestation/go/v1"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/carabiner-dev/ampel/internal/index"
)

const ClassName = "vex"

func New() *Transformer {
	return &Transformer{}
}

// Transformer implements the VEX interface
type Transformer struct{}

// Init satisfies the transformer interface. The VEX transformer takes no config today.
func (t *Transformer) Init(_ *structpb.Struct) error {
	return nil
}

// Mutate applies the VEX documents in the input to the received
// vulnerability reports.
func (t *Transformer) Mutate(subj attestation.Subject, inputs []attestation.Predicate) (attestation.Subject, []attestation.Predicate, error) {
	results, vexes, err := t.classifyAttestations(inputs)
	if err != nil {
		return nil, nil, fmt.Errorf("classifying attestations: %w", err)
	}

	// Check if we don't have a vulnerability report, then there is nothing
	// to transform, return the same inputs.
	if results == nil {
		logrus.Debugf("No vulnerability report found in attestation pack")
		return subj, inputs, nil
	}

	logrus.Debugf("VEX transformer: Got %d inputs, got results + %d vex documents", len(inputs), len(vexes))

	// Apply any VEX to documents received to the vulnerability report
	pred, err := t.ApplyVEX(subj, results, vexes)
	if err != nil {
		return nil, nil, fmt.Errorf("performing VEX mutation: %w", err)
	}
	return subj, []attestation.Predicate{pred}, nil
}

// classifyAttestations orders the received predictaes and separates the OSV
// results from the VEX data.
func (t *Transformer) classifyAttestations(predicates []attestation.Predicate) (*osv.Results, []attestation.Predicate, error) {
	var report *osv.Results
	var vexes []attestation.Predicate

	for _, p := range predicates {
		// Check if we got the vulnerability report
		if strings.HasPrefix(string(p.GetType()), "https://ossf.github.io/osv-schema/results") {
			if report != nil {
				return nil, nil, errors.New("more than one vulnerability report found in predicates")
			}

			// Ensure we can cast the report
			t, ok := p.GetParsed().(*osv.Results)
			if ok {
				report = t
				continue
			} else {
				logrus.Debugf("found OSV predicate but could not find results (got %T)", p.GetParsed())
			}
		}

		// Check if this is an openvex document:
		if strings.HasPrefix(string(p.GetType()), "https://openvex.dev/ns") {
			vexes = append(vexes, p)
		}
	}

	return report, vexes, nil
}

func hashToHash(intotoHash string) string {
	switch intotoHash {
	case string(gointoto.AlgorithmSHA256):
		return string(openvex.SHA256)
	case string(gointoto.AlgorithmSHA512):
		return string(openvex.SHA512)
	case string(gointoto.AlgorithmSHA1), string(gointoto.AlgorithmGitCommit), string(gointoto.AlgorithmGitTag):
		return string(openvex.SHA1)
	default:
		return ""
	}
}

// This converts an ecosystem package to a purl. For the full list
// of officially supported ecosystems see the file in this bucket:
// https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
func osvPackageToPurl(pkg *osv.Result_Package_Info) string {
	var ptype, version, namespacename, gov string
	switch pkg.GetEcosystem() {
	case "Go":
		ptype = "golang"
		version = pkg.GetVersion()
		if !strings.HasPrefix(version, "v") {
			gov = "v"
		}
		namespacename = pkg.GetName()
	default:
		return ""
	}
	return fmt.Sprintf("pkg:%s/%s@%s%s", ptype, namespacename, gov, version)
}

func normalizeVulnIds(record *osv.Record) (main openvex.VulnerabilityID, aliases []openvex.VulnerabilityID) {
	id := openvex.VulnerabilityID(record.GetId())
	aliases = []openvex.VulnerabilityID{id}
	for _, i := range record.Aliases {
		if strings.HasPrefix(i, "CVE-") {
			id = openvex.VulnerabilityID(i)
		}
		if !slices.Contains(aliases, openvex.VulnerabilityID(i)) {
			aliases = append(aliases, openvex.VulnerabilityID(i))
		}
	}

	slices.Sort(aliases)
	return id, aliases
}

// ApplyVEX applies a group of OpenVEX predicates to the vuln report
// and returns the vexed report
func (t *Transformer) ApplyVEX(
	subj attestation.Subject, report *osv.Results, vexes []attestation.Predicate,
) (attestation.Predicate, error) {
	if report == nil {
		return nil, fmt.Errorf("no vulnerability report found")
	}
	// Filter the applicable statements
	statements := extractStatements(vexes)
	logrus.Debugf("Filtered %d statements from %d OpenVEX predicates", len(statements), len(vexes))

	// Create the vex product from the policy subject
	hashes := map[openvex.Algorithm]openvex.Hash{}
	var pAlgo, pVal string
	for algo, val := range subj.GetDigest() {
		if pAlgo == "" && pVal == "" {
			pAlgo = algo
			pVal = val
		}
		h := hashToHash(algo)
		if h == "" {
			continue
		}
		hashes[openvex.Algorithm(h)] = openvex.Hash(val)
	}

	// Sythesize the product to match
	product := openvex.Product{}
	product.Hashes = hashes

	if subj.GetUri() != "" {
		product.ID = subj.GetUri()
		if strings.HasPrefix(subj.GetUri(), "pkg:") {
			product.Identifiers = map[openvex.IdentifierType]string{
				openvex.PURL: subj.GetUri(),
			}
		}
	}

	if product.ID == "" && pAlgo != "" {
		product.ID = fmt.Sprintf("%s:%s", pAlgo, pVal)
	}

	// Index the statements and get those that apply
	si, err := index.New(index.WithStatements(statements))
	if err != nil {
		return nil, fmt.Errorf("creating statement index")
	}

	logrus.Debugf("VEX Index: %+v", si)
	statements = si.Matches(index.WithProduct(&product))
	logrus.Debugf("Got %d statatements back applicable to product %+v", len(statements), product)

	// Now index the applicable statements
	productIndex, err := index.New(index.WithStatements(statements))
	if err != nil {
		return nil, fmt.Errorf("indexing produc statements: %w", err)
	}

	newReport := &osv.Results{
		Date:    report.GetDate(),
		Results: []*osv.Result{},
	}

	// This sucks, we need better indexing in the vex libraries
	for _, result := range report.Results {
		// Clone the result to the new one
		newResult := proto.CloneOf(result)
		newResult.Packages = []*osv.Result_Package{}

		for _, p := range result.GetPackages() {
			// Comput the package URL for the purl
			packagePurl := osvPackageToPurl(p.GetPackage())
			if packagePurl == "" {
				logrus.Debugf("Could not build purl from %+v, no matching possible", p)
				newResult.Packages = append(newResult.Packages, p)
				continue
			}

			// Clone the package entry, but reset the vulnerabilities
			newPackage := proto.CloneOf(p)
			newPackage.Vulnerabilities = []*osv.Record{}

			logrus.Debugf("Checking vulns for %s", packagePurl)

			// Assemble the filter pieces. First, the vuln:
			for _, v := range p.Vulnerabilities {
				id, aliases := normalizeVulnIds(v)
				ovuln := openvex.Vulnerability{
					Name:    id,
					Aliases: aliases,
				}

				logrus.Debugf("  Checking vexes for %s %+v", ovuln.Name, ovuln.Aliases)

				// Note that the scanner puts the affected package at the top
				// of the result struct, so no need to descend to the affected
				// data of the report.
				subc := &openvex.Subcomponent{
					Component: openvex.Component{
						ID: packagePurl,
						Identifiers: map[openvex.IdentifierType]string{
							openvex.PURL: packagePurl,
						},
					},
				}

				pstatements := productIndex.Matches(
					index.WithVulnerability(&ovuln),
					index.WithSubcomponent(subc),
				)
				logrus.Debugf("  VEX Index: %+v", productIndex)
				logrus.Debugf("  Got %d vex statements from indexer for %s + %s", len(pstatements), ovuln.Name, subc.ID)

				var statement *openvex.Statement
				for _, s := range pstatements {
					if statement == nil {
						statement = s
						continue
					}

					d := s.Timestamp
					if s.LastUpdated != nil {
						if s.LastUpdated.After(*d) {
							d = s.LastUpdated
						}
					}

					st := statement.Timestamp
					if statement.LastUpdated != nil {
						st = statement.LastUpdated
					}

					if d.After(*st) {
						statement = s
					}
				}

				// At this point we have the latest vex statement, we can now
				// check if we're not_affected :lolsob:
				if statement != nil && statement.Status == openvex.StatusNotAffected {
					logrus.Debugf("VEX data found for %s in %s, suppressing", v.GetId(), packagePurl)
					continue
				}

				// ... if not, then inlucde it in the new one.
				newPackage.Vulnerabilities = append(newPackage.Vulnerabilities, v)
			}

			if len(newPackage.Vulnerabilities) > 0 {
				newResult.Packages = append(newResult.Packages, newPackage)
			} else {
				logrus.Debugf("Vulnerabilities in %s are vexed. Skipping from report", packagePurl)
			}
		}
		newReport.Results = append(newReport.Results, newResult)
	}

	data, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(newReport)
	if err != nil {
		return nil, fmt.Errorf("marshaling new OSV report")
	}

	hsets, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(data)})
	if err != nil || len(*hsets) == 0 {
		return nil, fmt.Errorf("error hashing synthesised report: %w", err)
	}

	descr := hsets.ToResourceDescriptors()
	descr[0].Name = "synhetic_report_with_vex_applied"
	descr[0].Uri = "internal:vex"

	return &generic.Predicate{
		Type:   aosv.PredicateType,
		Parsed: newReport,
		Data:   data,
		Source: descr[0],
	}, nil
}

// extractStatements reads all the openvex predicates the statements
func extractStatements(preds []attestation.Predicate) []*openvex.Statement {
	ret := []*openvex.Statement{}
	for _, pred := range preds {
		doc, ok := pred.GetParsed().(*openvex.VEX)
		if !ok {
			logrus.Debugf("POSSIBLE BUG: predicate is %T instead of OpenVEX", pred.GetParsed())
			continue
		}

		// Cycle the VEX statements
		// TODO: This should be a doc.ExtractStatement func
		// update: done. Once this merges we reuse it:
		// https://github.com/openvex/go-vex/pull/131
		for i := range doc.Statements {
			// Carry over the dates from the doc
			if doc.Statements[i].Timestamp == nil {
				doc.Statements[i].Timestamp = doc.Timestamp
			}
			if doc.Statements[i].LastUpdated == nil {
				doc.Statements[i].LastUpdated = doc.LastUpdated
			}
			ret = append(ret, &doc.Statements[i])
		}
	}
	return ret
}
