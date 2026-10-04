// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package purl

import (
	"cel.dev/cel-go/cel"
	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
)

var Identity = class.MustParseIdentity("purl@v0")

type Plugin struct {
	Tool *PurlTool
}

func New() *Plugin {
	return &Plugin{
		Tool: &PurlTool{},
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
		"purl": p.Tool,
	}
}

func (p *Plugin) Identity() *class.Identity {
	return Identity
}
