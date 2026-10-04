// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package osv provides CEL helpers for writing policies over OSV results
// predicates. OSV data nests findings three levels deep:
//
//	(results -> packages -> vulnerabilities)
//
// and encodes severity as CVSS vector strings, which makes raw CEL policies
// verbose and error-prone. These plugin methods flatten the JSON traversal,
// expose alias aware id matching, and reuse the AMPEL cvss plugin scorer
// so authors can write intent-level checks.
package osv

import (
	"cel.dev/cel-go/cel"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"

	api "github.com/policylabs/ampel/pkg/api/v1"
	"github.com/policylabs/ampel/pkg/evaluator/class"
)

var Identity = class.MustParseIdentity("osv@v1")

type Plugin struct {
	Tool *OSVTool
}

func New() *Plugin {
	return &Plugin{
		Tool: &OSVTool{},
	}
}

func (p *Plugin) Capabilities() []api.Capability {
	return []api.Capability{
		api.CapabilityEvalEnginePlugin,
	}
}

func (p *Plugin) CanRegisterFor(c class.Class) bool {
	return c.Name() == "cel"
}

func (p *Plugin) Library() cel.EnvOption {
	return cel.Lib(p.Tool)
}

func (p *Plugin) VarValues(_ *papi.Policy, _ attestation.Subject, _ []attestation.Predicate) map[string]any {
	return map[string]any{
		"osv": p.Tool,
	}
}

func (p *Plugin) Identity() *class.Identity {
	return Identity
}
