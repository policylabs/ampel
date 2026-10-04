// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package semver provides a CEL-runtime plugin that exposes a
// `semver` object with helpers for parsing and comparing Semantic
// Versioning 2.0.0 strings. See docs/03-ampel-policy-guide.md for
// the list of exposed methods and usage examples.
package semver

import (
	"cel.dev/cel-go/cel"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"

	api "github.com/policylabs/ampel/pkg/api/v1"
	"github.com/policylabs/ampel/pkg/evaluator/class"
)

var Identity = class.MustParseIdentity("semver@v0")

// Plugin wires the semver tool into ampel's CEL evaluator.
type Plugin struct {
	Tool *SemverTool
}

// New returns a ready-to-register plugin instance.
func New() *Plugin {
	return &Plugin{Tool: &SemverTool{}}
}

func (p *Plugin) Capabilities() []api.Capability {
	return []api.Capability{api.CapabilityEvalEnginePlugin}
}

func (p *Plugin) CanRegisterFor(c class.Class) bool {
	return c.Name() == "cel"
}

func (p *Plugin) Library() cel.EnvOption {
	return cel.Lib(p.Tool)
}

func (p *Plugin) VarValues(_ *papi.Policy, _ attestation.Subject, _ []attestation.Predicate) map[string]any {
	return map[string]any{
		"semver": p.Tool,
	}
}

func (p *Plugin) Identity() *class.Identity {
	return Identity
}
