// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"bytes"
	"slices"

	"cel.dev/cel-go/cel"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/predicate/cyclonedx"
	"github.com/policylabs/collector/predicate/spdx"
	"github.com/policylabs/collector/predicate/spdx3"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/protobom/cel/pkg/elements"
	"github.com/protobom/cel/pkg/library"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/sirupsen/logrus"

	api "github.com/policylabs/ampel/pkg/api/v1"
	"github.com/policylabs/ampel/pkg/evaluator/class"
)

var Identity = class.MustParseIdentity("protobom@v0")

// sbomPredicateTypes lists the SBOM predicate types protobom's reader can
// parse into a document. Predicates of any other type are not SBOMs and never
// reach the sboms variable.
var sbomPredicateTypes = []attestation.PredicateType{
	spdx.PredicateType,
	spdx3.PredicateType,
	cyclonedx.PredicateType,
}

func New() *Plugin {
	return &Plugin{}
}

type Plugin struct{}

func (h *Plugin) Capabilities() []api.Capability {
	return []api.Capability{
		api.CapabilityEvalEnginePlugin,
	}
}

func (p *Plugin) CanRegisterFor(c class.Class) bool {
	return c.Name() == "cel"
}

func (p *Plugin) Library() cel.EnvOption {
	return library.NewProtobom().EnvOption()
}

func (p *Plugin) VarValues(_ *papi.Policy, _ attestation.Subject, preds []attestation.Predicate) map[string]any {
	sbomList := []any{}
	r := reader.New()
	logrus.Debugf("Inserting protobom vars (from %d predicates)", len(preds))
	for _, pred := range preds {
		if !slices.Contains(sbomPredicateTypes, pred.GetType()) {
			continue
		}
		doc, err := r.ParseStream(bytes.NewReader(pred.GetData()))
		if err != nil {
			// we cannot return errs so..
			continue
		}
		sbomList = append(sbomList, &elements.Document{
			Document: doc,
		})
	}

	return map[string]any{
		"protobom": elements.Protobom{},
		"sboms":    sbomList,
	}
}

func (p *Plugin) Identity() *class.Identity {
	return Identity
}
