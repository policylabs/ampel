// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"cel.dev/cel-go/cel"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"

	api "github.com/policylabs/ampel/pkg/api/v1"
	"github.com/policylabs/ampel/pkg/evaluator/class"
)

var Identity = class.MustParseIdentity("url@v0")

type Plugin struct {
	Tool *UrlTool
}

func New() *Plugin {
	return &Plugin{
		Tool: &UrlTool{},
	}
}

func (h *Plugin) Capabilities() []api.Capability {
	return []api.Capability{
		api.CapabilityEvalEnginePlugin,
	}
}

func (h *Plugin) CanRegisterFor(c class.Class) bool {
	return c.Name() == "cel"
}

func (h *Plugin) Library() cel.EnvOption {
	return cel.Lib(h.Tool)
}

func (h *Plugin) VarValues(_ *papi.Policy, _ attestation.Subject, _ []attestation.Predicate) map[string]any {
	return map[string]any{
		"url": h.Tool,
	}
}

func (h *Plugin) Identity() *class.Identity {
	return Identity
}
