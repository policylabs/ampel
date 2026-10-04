// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/carabiner-dev/termtable"
	papi "github.com/policylabs/policy/api/v1"
)

// dateFormat is the one-second-resolution layout used for result
// timestamps. Matches Go's default time.Time stringer minus the
// fractional seconds.
const dateFormat = "2006-01-02 15:04:05 -0700 MST"

// assertModeOR mirrors the verifier's assert mode label. A block in OR
// mode passes as soon as one of its policies does.
const assertModeOR = "OR"

// localDate renders t in the user's local zone at second resolution.
func localDate(t time.Time) string {
	return t.Local().Format(dateFormat)
}

// resultTable builds the single-result view: a 3-column table with a
// banner, a metadata block (label/value via a colspan=2 label), and a
// per-check rundown below.
func (d *Driver) resultTable(result *papi.Result) *termtable.Table {
	t := termtable.NewTable()

	d.banner(t, "Evaluation Results", 3)

	// Col 0 holds the Check ID (identifier-style) — bounded the same
	// way as the identifier columns in the other views.
	t.Column(0).Style("white-space: nowrap; min-width: 20%; max-width: 25")
	// Col 1 holds the Status in the per-check section (● PASS /
	// ● FAIL / ● SOFTFAIL) — same fixed 10-column slot as the other
	// views so the dot + label never splits and the widest case
	// (SOFTFAIL = 8 chars + dot + space = 10) fits exactly.
	t.Column(1).Style("white-space: nowrap; width: 10")

	switch {
	case result.GetMeta().GetDescription() != "":
		txt := result.GetMeta().GetDescription()
		if id := result.GetPolicy().GetId(); id != "" {
			txt = id + ": " + txt
		}
		// Explicitly wrap the description — it anchors at col 0 and
		// would otherwise inherit col 0's nowrap, clipping long
		// descriptions on narrow terminals.
		row := t.AddRow()
		row.AddCell(
			termtable.WithContent(txt),
			termtable.WithColSpan(3),
			termtable.WithMultiLine(),
		)
	case result.GetPolicy().GetId() != "":
		addLabeledRow(t, "ID", result.GetPolicy().GetId())
	}

	addLabeledRow(t, "Status",
		fmt.Sprintf("%s %s", d.Decorator.StatusToDot(result.Status), d.Decorator.Bold(result.Status)))
	addLabeledRow(t, "Results Date", localDate(result.DateEnd.AsTime()),
		termtable.WithCellStyle("white-space: nowrap"))
	addLabeledRow(t, "Execution Time", fmt.Sprint(result.DateEnd.AsTime().Sub(result.DateStart.AsTime())))
	addLabeledRow(t, "Tenets", d.Decorator.TenetsToString(result))
	addLabeledRow(t, "Subject", d.Decorator.SubjectToString(result.Subject, result.Chain))
	if len(result.GetMeta().GetControls()) > 0 {
		addLabeledRow(t, "Controls", d.Decorator.ControlsToString(result, "", ""))
	}

	head := t.AddRow()
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Check")))
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Status")))
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Message")))

	for i, er := range result.GetEvalResults() {
		cell := ""
		switch {
		case er.Status == papi.StatusSKIP:
			// Skips explain themselves through their assessment
			cell = d.Decorator.SkipToString(er.GetAssessment())
		case er.Status != papi.StatusPASS:
			cell = d.Decorator.ErrorToString(er.Error)
		case er.GetAssessment() != nil:
			cell = d.Decorator.AssessmentToString(er.GetAssessment())
		}
		row := t.AddRow()
		row.AddCell(termtable.WithContent(
			d.Decorator.ControlsToString(result, er.Id, fmt.Sprintf("%d", i))))
		row.AddCell(termtable.WithContent(
			fmt.Sprintf("%s %s", d.Decorator.StatusToDot(er.Status), er.Status)))
		row.AddCell(termtable.WithContent(cell))
	}
	return t
}

// resultSetTable builds the 4-column table for a policy-set evaluation:
// banner, a header line with set ID and date, a subject block, then one
// row per contained result or group.
func (d *Driver) resultSetTable(set *papi.ResultSet) *termtable.Table {
	t := termtable.NewTable()

	d.banner(t, "Evaluation Results", 4)

	// Keep the Policy and Controls columns on a single line — their
	// contents are identifier-style and wrapping them mid-ID across
	// multiple rendered lines hurts readability. Bound each to
	// [20 %, 25 chars] so they claim a visible chunk of the target
	// even when content is short, and trim with an ellipsis when
	// content is long.
	t.Column(0).Style("white-space: nowrap; min-width: 20%; max-width: 25")
	t.Column(1).Style("white-space: nowrap; min-width: 20%; max-width: 25")
	// Status is always one of PASS / FAIL / SOFTFAIL, formatted as
	// "{dot} {STATUS}" — 1 + 1 + 8 = 10 display columns at the widest.
	// Pin the column so the status dot + label never splits across
	// lines and the grid stays tidy at any target width.
	t.Column(2).Style("white-space: nowrap; width: 10")

	idRow := t.AddRow()
	idRow.AddCell(termtable.WithContent(d.Decorator.Bold("PolicySet")))
	idRow.AddCell(termtable.WithContent(set.GetPolicySet().GetId()))
	idRow.AddCell(termtable.WithContent(d.Decorator.Bold("Date")))
	idRow.AddCell(
		termtable.WithContent(localDate(set.DateEnd.AsTime())),
		termtable.WithCellStyle("white-space: nowrap"),
	)

	if s := set.GetSubject(); s != nil {
		st := subjectSummary(s)
		row := t.AddRow()
		row.AddCell(termtable.WithContent(
			fmt.Sprintf("Status: %s %s",
				d.Decorator.StatusToDot(set.Status), d.Decorator.Bold(set.Status))))
		row.AddCell(termtable.WithContent("Subject"))
		row.AddCell(termtable.WithContent(st), termtable.WithColSpan(2))
	}

	head := t.AddRow()
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Policy")))
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Controls")))
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Status")))
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Details")))

	for _, r := range set.GetResults() {
		assessments := collectAssessments(d, r)
		controls := "-"
		if len(r.GetMeta().GetControls()) > 0 {
			controls = d.Decorator.ControlsToString(r, "", "")
		}
		row := t.AddRow()
		row.AddCell(termtable.WithContent(r.GetPolicy().GetId()))
		row.AddCell(termtable.WithContent(controls))
		row.AddCell(termtable.WithContent(
			fmt.Sprintf("%s %s", d.Decorator.StatusToDot(r.Status), d.Decorator.Bold(r.Status))))
		row.AddCell(termtable.WithContent(assessments))
	}

	for _, grp := range set.GetGroups() {
		id := grp.GetGroup().GetId()
		message := groupSummary(d, grp)
		controls := "-"
		if len(grp.GetMeta().GetControls()) > 0 {
			controls = d.Decorator.ControlsToString(&papi.Result{
				Meta: &papi.Meta{Controls: grp.GetMeta().GetControls()},
			}, "", "")
		}
		row := t.AddRow()
		row.AddCell(termtable.WithContent(id))
		row.AddCell(termtable.WithContent(controls))
		row.AddCell(termtable.WithContent(
			fmt.Sprintf("%s %s", d.Decorator.StatusToDot(grp.GetStatus()), d.Decorator.Bold(grp.GetStatus()))))
		row.AddCell(termtable.WithContent(message))
	}

	return t
}

// resultGroupTable builds the 4-column table for a group evaluation:
// banner, group ID + date line, subject block, then one row per
// evaluated policy block.
func (d *Driver) resultGroupTable(grp *papi.ResultGroup) *termtable.Table {
	t := termtable.NewTable()

	d.banner(t, "Evaluation Results", 4)

	// Mirror the policy-set layout: cols 0 & 1 are identifier-style
	// (nowrap, [20 %, 25]), col 2 is the fixed-width status slot
	// (just wide enough for "● SOFTFAIL"), col 3 (Details) wraps
	// free-form text.
	t.Column(0).Style("white-space: nowrap; min-width: 20%; max-width: 25")
	t.Column(1).Style("white-space: nowrap; min-width: 20%; max-width: 25")
	t.Column(2).Style("white-space: nowrap; width: 10")

	idRow := t.AddRow()
	idRow.AddCell(termtable.WithContent(d.Decorator.Bold("PolicyGroup")))
	idRow.AddCell(termtable.WithContent(grp.GetGroup().GetId()))
	idRow.AddCell(termtable.WithContent(d.Decorator.Bold("Date")))
	idRow.AddCell(
		termtable.WithContent(localDate(grp.DateEnd.AsTime())),
		termtable.WithCellStyle("white-space: nowrap"),
	)

	if s := grp.GetSubject(); s != nil {
		st := subjectSummary(s)
		row := t.AddRow()
		row.AddCell(termtable.WithContent(
			d.Decorator.Bold("Status:") +
				fmt.Sprintf(" %s %s",
					d.Decorator.StatusToDot(grp.GetStatus()),
					d.Decorator.Bold(grp.GetStatus()))))
		row.AddCell(termtable.WithContent(d.Decorator.Bold("Subject")))
		row.AddCell(termtable.WithContent(st), termtable.WithColSpan(2))
	}

	head := t.AddRow()
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Policy Block")))
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Controls")))
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Status")))
	head.AddCell(termtable.WithContent(d.Decorator.Bold("Details")))

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
			controls = d.Decorator.ControlsToString(&papi.Result{
				Meta: &papi.Meta{Controls: r.GetMeta().GetControls()},
			}, "", "")
		}

		row := t.AddRow()
		row.AddCell(termtable.WithContent(id))
		row.AddCell(termtable.WithContent(controls))
		row.AddCell(termtable.WithContent(
			fmt.Sprintf("%s %s", d.Decorator.StatusToDot(r.Status), d.Decorator.Bold(r.Status))))
		row.AddCell(termtable.WithContent(message))
	}

	return t
}

// banner places the Ampel banner as the first row, spanning cols
// left-aligned.
func (d *Driver) banner(t *termtable.Table, legend string, cols int) {
	row := t.AddRow()
	row.AddCell(
		termtable.WithContent(d.Decorator.AmpelBanner(legend)),
		termtable.WithColSpan(cols),
		termtable.WithAlign(termtable.AlignLeft),
	)
}

// addLabeledRow adds a {label (colspan 2), value} row — the metadata
// shape used by the single-result table. Any cell options passed via
// valueOpts are applied to the value cell (in addition to its content),
// so callers can e.g. prevent wrapping on a specific row.
func addLabeledRow(t *termtable.Table, label, value string, valueOpts ...termtable.CellOption) {
	row := t.AddRow()
	row.AddCell(termtable.WithContent(label), termtable.WithColSpan(2))
	row.AddCell(append([]termtable.CellOption{termtable.WithContent(value)}, valueOpts...)...)
}

// subjectSummary formats a subject's name + truncated digests. The
// layout here mirrors the original go-pretty rendering for continuity
// with the markdown and html drivers.
func subjectSummary(s interface {
	GetName() string
	GetDigest() map[string]string
},
) string {
	var b strings.Builder
	if s.GetName() != "" {
		b.WriteString(s.GetName())
		b.WriteByte('\n')
	}
	for algo, val := range s.GetDigest() {
		cut := int(math.Min(32, float64(len(val))))
		fmt.Fprintf(&b, "- %s:%s...\n", algo, val[0:cut])
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// collectAssessments concatenates the per-check assessments / errors
// that should appear in the Details column of a ResultSet row.
func collectAssessments(d *Driver, r *papi.Result) string {
	var b strings.Builder
	for _, er := range r.GetEvalResults() {
		switch {
		case er.GetStatus() == papi.StatusSKIP:
			b.WriteString(d.Decorator.SkipToString(er.GetAssessment()))
			b.WriteByte('\n')
		case er.GetStatus() == papi.StatusPASS && r.GetStatus() == papi.StatusPASS:
			b.WriteString(er.GetAssessment().GetMessage())
			b.WriteByte('\n')
		case er.GetStatus() != papi.StatusPASS && r.GetStatus() != papi.StatusPASS:
			line := er.GetError().GetMessage() + "\n"
			if !strings.Contains(b.String(), line) {
				b.WriteString(d.Decorator.ErrorToString(er.GetError()))
			}
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

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

// groupSummary builds the Details-column text for a result-group row
// inside a ResultSet — pass messages on success, dedup'd error
// messages on failure.
func groupSummary(d *Driver, grp *papi.ResultGroup) string {
	_ = d
	if grp.GetStatus() == papi.StatusPASS {
		msgs := []string{}
		seen := map[string]struct{}{}
		for _, block := range grp.GetEvalResults() {
			prefix := ""
			if ctls := block.GetMeta().GetControls(); len(ctls) > 0 {
				labels := make([]string, 0, len(ctls))
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
		return strings.Join(msgs, "\n")
	}

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
	return strings.Join(msgs, "\n")
}
