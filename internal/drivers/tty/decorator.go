// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	gww "github.com/mitchellh/go-wordwrap"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
)

type Decorator struct{}

// Color functions
var (
	r  = color.New(color.FgRed, color.BgBlack).SprintFunc()
	y  = color.New(color.FgYellow, color.BgBlack).SprintFunc()
	g  = color.New(color.FgGreen, color.BgBlack).SprintFunc()
	w1 = color.New(color.FgHiWhite, color.BgBlack).SprintFunc()
	w2 = color.New(color.Faint, color.FgWhite, color.BgBlack).SprintFunc()
)

func (d *Decorator) AssessmentToString(a *papi.Assessment) string {
	return w2("✔ " + a.GetMessage())
}

// SkipToString renders the reason an element was skipped.
func (d *Decorator) SkipToString(a *papi.Assessment) string {
	return w2(a.GetMessage())
}

func (d *Decorator) AmpelBanner(legend string) string {
	if legend != "" {
		legend = w2(": " + legend)
	}
	return fmt.Sprintf("%s%s%s%s%s", r("⬤"), y("⬤"), g("⬤"), w1(strings.ToUpper("AMPEL")), legend)
}

func (d *Decorator) StatusToDot(status string) string {
	switch status {
	case papi.StatusFAIL:
		return r("●")
	case papi.StatusPASS:
		return g("●")
	case papi.StatusSOFTFAIL:
		return y("●")
	case papi.StatusSKIP:
		return w2("○")
	default:
		return "?"
	}
}

func (d *Decorator) SubjectToString(subject attestation.Subject, chain []*papi.ChainedSubject) string {
	predata := ""
	for _, subsubj := range chain {
		predata += d.SubjectToString(subsubj.Source, nil) + "\n↳ "
	}
	if subject == nil {
		return predata + "(N/A)"
	}

	if subject.GetName() != "" {
		ret := predata + subject.GetName()
		for algo, val := range subject.GetDigest() {
			ret += fmt.Sprintf("\n  %s:%s...", algo, val[0:32])
		}
		return ret
	}

	if subject.GetUri() != "" {
		return predata + subject.GetUri()
	}

	for algo, val := range subject.GetDigest() {
		return predata + fmt.Sprintf("%s:%s", algo, val)
	}
	return predata + ""
}

func (d *Decorator) ErrorToString(err *papi.Error) string {
	if err == nil {
		return ""
	}

	res := err.Message
	if err.Guidance != "" {
		res += "\n" + gww.WrapString(err.Guidance, 55)
	}
	return res
}

func (d *Decorator) ControlsToString(result *papi.Result, checkID, def string) string {
	checks := make([]string, 0, len(result.Meta.Controls))
	for _, c := range result.Meta.Controls {
		ret := ""
		ret += c.Class
		if c.Class != "" {
			ret += "-"
		}
		ret += c.Id

		if checkID != "" {
			ret += "." + checkID
		} else if def != "" {
			ret = "--"
		}
		checks = append(checks, strings.TrimSpace(ret))
	}
	return strings.Join(checks, "\n")
}

func (d *Decorator) TenetsToString(result *papi.Result) string {
	ret := fmt.Sprintf("%d ", len(result.EvalResults))
	var pass, fail, softfail, skip int
	for _, r := range result.EvalResults {
		switch r.Status {
		case papi.StatusFAIL:
			fail++
		case papi.StatusSOFTFAIL:
			softfail++
		case papi.StatusPASS:
			pass++
		case papi.StatusSKIP:
			skip++
		}
	}

	statuses := []string{}
	if pass > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", pass, papi.StatusPASS))
	}
	if softfail > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", softfail, papi.StatusSOFTFAIL))
	}
	if fail > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", fail, papi.StatusFAIL))
	}
	if skip > 0 {
		statuses = append(statuses, fmt.Sprintf("%d %s", skip, papi.StatusSKIP))
	}
	ret += fmt.Sprintf("(%s)", strings.Join(statuses, " | "))
	ret += " Mode: " + result.Meta.AssertMode
	return ret
}

func (d *Decorator) Bold(txt string) string {
	return w1(txt)
}
