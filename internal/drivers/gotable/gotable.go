// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package gotable transforms evaluation results to a go table object,
// from there it can be rendererd to html, markup, etc.
package gotable

import (
	"fmt"
	"math"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
)

const headerSubject = "Subject"

// assertModeOR mirrors the verifier's assert mode label. A block in OR
// mode passes as soon as one of its policies does.
const assertModeOR = "OR"

// blockAssessments returns the assessment messages of the policies that
// carried a block to PASS, in evaluation order and dedup'd.
//
// Under the default AND assert mode every policy in the block has to
// pass, so all of their messages are reported. Under OR a single passing
// policy decides the block, so only that policy's messages are reported:
// the rest either failed or never got to run under lazy evaluation.
func blockAssessments(block *papi.BlockEvalResult) []string {
	orMode := block.GetMeta().GetAssertMode() == assertModeOR
	msgs := []string{}
	seen := map[string]struct{}{}
	for _, res := range block.GetResults() {
		if res.GetStatus() != papi.StatusPASS {
			continue
		}
		added := false
		for _, er := range res.GetEvalResults() {
			if er.GetStatus() != papi.StatusPASS {
				continue
			}
			msg := er.GetAssessment().GetMessage()
			if msg == "" {
				continue
			}
			if _, ok := seen[msg]; ok {
				// Still the deciding policy under OR, just nothing new to say.
				added = true
				continue
			}
			seen[msg] = struct{}{}
			msgs = append(msgs, msg)
			added = true
		}
		// Keep looking if the deciding policy had nothing to report, so an
		// OR block does not end up with an empty cell.
		if orMode && added {
			break
		}
	}
	return msgs
}

type TableBuilder struct {
	Decorator TableDecorator
}

// TableDecorator is an object that renders the format specific
// decoration of the tabular reports.
type TableDecorator interface {
	AmpelBanner(string) string
	SubjectToString(attestation.Subject, []*papi.ChainedSubject) string
	AssessmentToString(*papi.Assessment) string
	ErrorToString(*papi.Error) string
	StatusToDot(string) string
	ControlsToString(result *papi.Result, checkID, def string) string
	TenetsToString(result *papi.Result) string
	Bold(string) string
}

// RenderResult renders a single evaluation result
func (tb *TableBuilder) ResultsTable(result *papi.Result) (table.Writer, error) {
	t := table.NewWriter()

	rowConfigAutoMerge := table.RowConfig{
		AutoMerge:      true,
		AutoMergeAlign: text.AlignLeft,
	}
	banner := tb.Decorator.AmpelBanner("Evaluation Results")
	t.AppendRow(table.Row{banner, banner, banner}, rowConfigAutoMerge)
	t.AppendSeparator()
	if result.Meta.Description != "" {
		txt := result.Meta.Description
		if result.Policy.Id != "" {
			txt = result.Policy.Id + ": " + txt
		}
		t.AppendRow(table.Row{txt, txt, txt}, rowConfigAutoMerge)
		t.AppendSeparator()
	} else if result.Policy.Id != "" {
		t.AppendRow(table.Row{"ID", "ID", result.Policy.Id}, rowConfigAutoMerge)
	}

	t.AppendRow(table.Row{"Status", "Status", fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(result.Status), tb.Decorator.Bold(result.Status))}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Results Date", "Results Date", result.DateEnd.AsTime().Local()}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Execution Time", "Execution Time", result.DateEnd.AsTime().Sub(result.DateStart.AsTime())}, rowConfigAutoMerge)
	t.AppendRow(table.Row{"Tenets", "Tenets", tb.Decorator.TenetsToString(result)}, rowConfigAutoMerge)
	t.AppendRow(table.Row{headerSubject, headerSubject, tb.Decorator.SubjectToString(result.Subject, result.Chain)}, rowConfigAutoMerge)
	if len(result.GetMeta().Controls) > 0 {
		t.AppendRow(table.Row{"Controls", "Controls", tb.Decorator.ControlsToString(result, "", "")}, rowConfigAutoMerge)
	}
	t.AppendSeparator()
	t.AppendRow(table.Row{tb.Decorator.Bold("Check"), tb.Decorator.Bold("Status"), tb.Decorator.Bold("Message")})
	t.AppendSeparator()

	for i, er := range result.GetEvalResults() {
		cell := ""
		switch {
		case er.Status == papi.StatusSKIP:
			// Skips explain themselves through their assessment
			cell = er.GetAssessment().GetMessage()
		case er.Status != papi.StatusPASS:
			cell = tb.Decorator.ErrorToString(er.Error)
		case er.GetAssessment() != nil:
			cell = tb.Decorator.AssessmentToString(er.GetAssessment())
		}
		t.AppendRow(
			table.Row{
				tb.Decorator.ControlsToString(result, er.Id, fmt.Sprintf("%d", i)),
				fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(er.Status), er.Status),
				cell,
			},
		)
	}
	return t, nil
}

// RenderResult renders a single evaluation result
func (tb *TableBuilder) ResultSetTable(set *papi.ResultSet) (table.Writer, error) {
	t := table.NewWriter()

	rowConfigAutoMerge := table.RowConfig{
		AutoMerge:      true,
		AutoMergeAlign: text.AlignLeft,
	}
	banner := tb.Decorator.AmpelBanner("Evaluation Results")
	t.AppendRow(table.Row{banner, banner, banner, banner}, rowConfigAutoMerge)
	t.AppendSeparator()
	t.AppendRow(table.Row{tb.Decorator.Bold("PolicySet"), set.GetPolicySet().GetId(), tb.Decorator.Bold("Date"), set.DateEnd.AsTime().Local()})
	t.AppendSeparator()
	if s := set.GetSubject(); s != nil {
		st := ""
		if s.GetName() != "" {
			st += s.GetName() + "\n"
		}
		for algo, val := range s.GetDigest() {
			// This will prevent a panic if the subject hash is short, but it should never
			strlen := math.Min(32, float64(len(val)))
			st += fmt.Sprintf("- %s:%s...\n", algo, val[0:int(strlen)])
		}
		st = strings.TrimSuffix(st, "\n")
		t.AppendRow(
			table.Row{
				fmt.Sprintf("Status: %s %s", tb.Decorator.StatusToDot(set.Status), tb.Decorator.Bold(set.Status)),
				headerSubject, st, st,
			},
			rowConfigAutoMerge,
		)
	}
	t.AppendSeparator()
	t.AppendRow(table.Row{tb.Decorator.Bold("Policy"), tb.Decorator.Bold("Controls"), tb.Decorator.Bold("Status"), tb.Decorator.Bold("Details")})
	t.AppendSeparator()
	for _, r := range set.GetResults() {
		assessments := ""
		for _, er := range r.GetEvalResults() {
			switch {
			case er.GetStatus() == papi.StatusSKIP:
				assessments += er.GetAssessment().GetMessage() + "\n"
			case er.GetStatus() == papi.StatusPASS && r.GetStatus() == papi.StatusPASS:
				assessments += er.GetAssessment().GetMessage() + "\n"
			case er.GetStatus() != papi.StatusPASS && r.GetStatus() != papi.StatusPASS:
				if !strings.Contains(assessments, er.GetError().GetMessage()+"\n") {
					assessments += tb.Decorator.ErrorToString(er.GetError())
				}
			}
		}
		assessments = strings.TrimSuffix(assessments, "\n")

		controls := "-"
		if len(r.GetMeta().GetControls()) > 0 {
			controls = tb.Decorator.ControlsToString(r, "", "")
		}
		t.AppendRow(
			table.Row{
				r.GetPolicy().GetId(),
				controls,
				fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(r.Status), tb.Decorator.Bold(r.Status)),
				assessments,
			},
		)
	}
	for _, grp := range set.GetGroups() {
		id := grp.GetGroup().GetId()

		var message string
		if grp.GetStatus() == papi.StatusPASS {
			msgs := []string{}
			seen := map[string]struct{}{}
			for _, block := range grp.GetEvalResults() {
				prefix := ""
				if ctls := block.GetMeta().GetControls(); len(ctls) > 0 {
					labels := []string{}
					for _, ctl := range ctls {
						labels = append(labels, ctl.Label())
					}
					prefix = "[" + strings.Join(labels, ", ") + "] "
				}
				for _, msg := range blockAssessments(block) {
					line := prefix + msg
					if _, ok := seen[line]; !ok {
						seen[line] = struct{}{}
						msgs = append(msgs, line)
					}
				}
			}
			message = strings.Join(msgs, "\n")
		} else {
			msgs := []string{}
			seen := map[string]struct{}{}
			for _, block := range grp.GetEvalResults() {
				if block.GetStatus() != papi.StatusFAIL {
					continue
				}
				if msg := block.GetError().GetMessage(); msg != "" {
					if _, ok := seen[msg]; !ok {
						seen[msg] = struct{}{}
						msgs = append(msgs, msg)
					}
				}
			}
			message = strings.Join(msgs, "\n")
		}

		controls := "-"
		if len(grp.GetMeta().GetControls()) > 0 {
			controls = tb.Decorator.ControlsToString(&papi.Result{
				Meta: &papi.Meta{
					Controls: grp.GetMeta().GetControls(),
				},
			}, "", "")
		}
		t.AppendRow(
			table.Row{
				id, controls,
				fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(grp.GetStatus()), tb.Decorator.Bold(grp.GetStatus())),
				message,
			},
		)
	}
	return t, nil
}

// ResultGroupTable renders a single group evaluation result
func (tb *TableBuilder) ResultGroupTable(grp *papi.ResultGroup) (table.Writer, error) {
	t := table.NewWriter()

	rowConfigAutoMerge := table.RowConfig{
		AutoMerge:      true,
		AutoMergeAlign: text.AlignLeft,
	}
	banner := tb.Decorator.AmpelBanner("Evaluation Results")
	t.AppendRow(table.Row{banner, banner, banner, banner}, rowConfigAutoMerge)
	t.AppendSeparator()
	t.AppendRow(table.Row{tb.Decorator.Bold("PolicyGroup"), grp.GetGroup().GetId(), tb.Decorator.Bold("Date"), grp.DateEnd.AsTime().Local()})
	t.AppendSeparator()
	if s := grp.GetSubject(); s != nil {
		st := ""
		if s.GetName() != "" {
			st += s.GetName() + "\n"
		}
		for algo, val := range s.GetDigest() {
			// This will prevent a panic if the subject hash is short, but it should never
			strlen := math.Min(32, float64(len(val)))
			st += fmt.Sprintf("- %s:%s...\n", algo, val[0:int(strlen)])
		}
		st = strings.TrimSuffix(st, "\n")
		t.AppendRow(
			table.Row{
				tb.Decorator.Bold("Status:") + fmt.Sprintf(" %s %s", tb.Decorator.StatusToDot(grp.GetStatus()), tb.Decorator.Bold(grp.GetStatus())),
				tb.Decorator.Bold(headerSubject), st, st,
			},
			rowConfigAutoMerge,
		)
	}
	t.AppendSeparator()
	t.AppendRow(table.Row{tb.Decorator.Bold("Policy Block"), tb.Decorator.Bold("Controls"), tb.Decorator.Bold("Status"), tb.Decorator.Bold("Details")})
	t.AppendSeparator()
	for i, r := range grp.GetEvalResults() {
		id := r.GetId()
		if id == "" {
			id = fmt.Sprintf("Block #%d", i)
		}

		var message string
		if r.GetStatus() == papi.StatusPASS {
			message = strings.Join(blockAssessments(r), "\n")
			// Fall back to the policy count when the passing policies
			// define no assessment messages.
			if message == "" {
				message = fmt.Sprintf("(%d policies)", len(r.Results))
			}
		} else {
			message = r.GetError().GetMessage()
			if r.GetError().GetGuidance() != "" {
				message = "\n" + r.GetError().GetGuidance()
			}
		}

		controls := "-"
		if len(r.GetMeta().GetControls()) > 0 {
			controls = tb.Decorator.ControlsToString(&papi.Result{
				Meta: &papi.Meta{
					Controls: r.GetMeta().GetControls(),
				},
			}, "", "")
		}
		t.AppendRow(
			table.Row{
				id,
				controls,
				fmt.Sprintf("%s %s", tb.Decorator.StatusToDot(r.Status), tb.Decorator.Bold(r.Status)),
				message,
			},
		)
	}
	return t, nil
}
