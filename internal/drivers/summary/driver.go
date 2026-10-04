// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package summary implements a rendering driver that outputs the
// evaluation results as a single traffic-light line, suitable for
// compact destinations such as the GitHub Actions step summary.
package summary

import (
	"fmt"
	"io"
	"strings"

	papi "github.com/carabiner-dev/policy/api/v1"
)

// New returns a new summary driver
func New() *Driver {
	return &Driver{}
}

// Driver renders evaluation results as a single line
type Driver struct{}

func dot(status string) string {
	switch status {
	case papi.StatusFAIL:
		return "🔴"
	case papi.StatusPASS:
		return "🟢"
	default:
		return "🟡"
	}
}

func policyID(r *papi.Result) string {
	if id := r.GetPolicy().GetId(); id != "" {
		return id
	}
	return "policy"
}

func groupID(g *papi.ResultGroup) string {
	if id := g.GetGroup().GetId(); id != "" {
		return id
	}
	return "policy group"
}

// decidingMessage returns the message from the eval result that decided
// the policy status: the first tenet whose status matches the policy's,
// preferring tenets that evaluated evidence over those that errored
// before evaluating (eg for lack of attestations).
func decidingMessage(r *papi.Result) string {
	var deciding *papi.EvalResult
	for _, er := range r.GetEvalResults() {
		if er.GetStatus() != r.GetStatus() {
			continue
		}
		if deciding == nil {
			deciding = er
		}
		if len(er.GetStatements()) > 0 {
			deciding = er
			break
		}
	}
	if deciding == nil && len(r.GetEvalResults()) > 0 {
		deciding = r.GetEvalResults()[0]
	}

	if msg := deciding.GetAssessment().GetMessage(); msg != "" {
		return msg
	}
	if msg := deciding.GetError().GetMessage(); msg != "" {
		return msg
	}
	if msg := r.GetMeta().GetDescription(); msg != "" {
		return msg
	}
	status := r.GetStatus()
	if status == "" {
		status = "evaluated"
	}
	return "policy " + strings.ToLower(status)
}

// groupMessage returns the message of the block that decided the group
// status, drilling into its policy results for a more specific one.
func groupMessage(g *papi.ResultGroup) string {
	var deciding *papi.BlockEvalResult
	for _, ber := range g.GetEvalResults() {
		if ber.GetStatus() == g.GetStatus() {
			deciding = ber
			break
		}
	}
	if deciding == nil && len(g.GetEvalResults()) > 0 {
		deciding = g.GetEvalResults()[0]
	}

	if msg := deciding.GetError().GetMessage(); msg != "" {
		return msg
	}
	for _, r := range deciding.GetResults() {
		if r.GetStatus() == g.GetStatus() {
			return decidingMessage(r)
		}
	}
	if msg := g.GetMeta().GetDescription(); msg != "" {
		return msg
	}
	status := g.GetStatus()
	if status == "" {
		status = "evaluated"
	}
	return "policy group " + strings.ToLower(status)
}

// RenderResult writes the policy result as a single line
func (d *Driver) RenderResult(w io.Writer, result *papi.Result) error {
	_, err := fmt.Fprintf(
		w, "%s %s: %s\n", dot(result.GetStatus()), policyID(result), decidingMessage(result),
	)
	return err
}

// RenderResultGroup writes the group result as a single line
func (d *Driver) RenderResultGroup(w io.Writer, group *papi.ResultGroup) error {
	_, err := fmt.Fprintf(
		w, "%s %s: %s\n", dot(group.GetStatus()), groupID(group), groupMessage(group),
	)
	return err
}

// RenderResultSet writes the whole resultset as a single line. Sets with
// a single policy or group render as that unit's line; larger sets lead
// with the first failing (or softfailing) unit and a failure count.
func (d *Driver) RenderResultSet(w io.Writer, rset *papi.ResultSet) error {
	results := rset.GetResults()
	groups := rset.GetGroups()
	total := len(results) + len(groups)

	if total == 1 {
		if len(results) == 1 {
			return d.RenderResult(w, results[0])
		}
		return d.RenderResultGroup(w, groups[0])
	}

	prefix := ""
	if id := rset.GetPolicySet().GetId(); id != "" {
		prefix = id + ": "
	}
	overall := dot(rset.GetStatus())

	if total == 0 {
		msg := "no policy results found"
		if m := rset.GetError().GetMessage(); m != "" {
			msg = m
		}
		_, err := fmt.Fprintf(w, "%s %s%s\n", overall, prefix, msg)
		return err
	}

	var failed, soft int
	var failedID, failedMsg, softID, softMsg string
	for _, r := range results {
		switch r.GetStatus() {
		case papi.StatusPASS:
		case papi.StatusFAIL:
			if failed == 0 {
				failedID, failedMsg = policyID(r), decidingMessage(r)
			}
			failed++
		default:
			if soft == 0 {
				softID, softMsg = policyID(r), decidingMessage(r)
			}
			soft++
		}
	}
	for _, g := range groups {
		switch g.GetStatus() {
		case papi.StatusPASS:
		case papi.StatusFAIL:
			if failed == 0 {
				failedID, failedMsg = groupID(g), groupMessage(g)
			}
			failed++
		default:
			if soft == 0 {
				softID, softMsg = groupID(g), groupMessage(g)
			}
			soft++
		}
	}

	var err error
	switch {
	case failed > 0:
		_, err = fmt.Fprintf(
			w, "%s %s%s: %s (%d of %d policies failed)\n",
			overall, prefix, failedID, failedMsg, failed, total,
		)
	case soft > 0:
		_, err = fmt.Fprintf(
			w, "%s %s%s: %s (%d of %d policies softfailed)\n",
			overall, prefix, softID, softMsg, soft, total,
		)
	default:
		_, err = fmt.Fprintf(w, "%s %sall %d policies passed\n", overall, prefix, total)
	}
	return err
}
