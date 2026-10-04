// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"cel.dev/cel-go/cel"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
)

var Identity = class.MustParseIdentity("hasher@v0")

type Plugin struct {
	Hasher *Hasher
}

func New() *Plugin {
	return &Plugin{
		Hasher: &Hasher{},
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
	return cel.Lib(h.Hasher)
}

func (h *Plugin) VarValues(_ *papi.Policy, _ attestation.Subject, _ []attestation.Predicate) map[string]any {
	algos := make([]string, 0, len(intoto.HashAlgorithms))
	for algo := range intoto.HashAlgorithms {
		algos = append(algos, algo)
	}

	return map[string]any{
		"hashAlgorithms": algos,
		"hasher":         h.Hasher,
	}
}

func (h *Plugin) Identity() *class.Identity {
	return Identity
}
