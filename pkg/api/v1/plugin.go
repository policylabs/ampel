// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"reflect"

	"github.com/policylabs/ampel/pkg/evaluator/class"
)

type Capability string

var (
	CapabilityPredicateParser      = Capability("PredicateParser")
	CapabilityEnvelopeParser       = Capability("EnvelopeParser")
	CapabilityStatementParser      = Capability("StatementParser")
	CapabilityPredicateTransformer = Capability("PredicateTransformer")
	CapabilitySignatureVerifier    = Capability("SignatureVerifier")
	CapabilityEvalEnginePlugin     = Capability("EvalEnginePlugin")
)

var Capabilities = map[Capability]reflect.Type{
	CapabilityPredicateParser:      reflect.TypeOf((*PredicateParser)(nil)).Elem(),
	CapabilityEnvelopeParser:       reflect.TypeOf((*EnvelopeParser)(nil)).Elem(),
	CapabilityStatementParser:      reflect.TypeOf((*StatementParser)(nil)).Elem(),
	CapabilityPredicateTransformer: reflect.TypeOf((*PredicateTransformer)(nil)).Elem(),
	CapabilitySignatureVerifier:    reflect.TypeOf((*SignatureVerifier)(nil)).Elem(),
	CapabilityEvalEnginePlugin:     reflect.TypeOf((*EvalEnginePlugin)(nil)).Elem(),
}

type Plugin interface {
	Capabilities() []Capability
}

func PluginHasCapability(capability Capability, plugin Plugin) bool {
	pluginType := reflect.TypeOf(plugin)
	if _, ok := Capabilities[capability]; !ok {
		return false
	}
	return pluginType.Implements(Capabilities[capability])
}

type (
	PredicateParser      interface{} //nolint:iface // To be backfilled
	EnvelopeParser       interface{} //nolint:iface // To be backfilled
	StatementParser      interface{} //nolint:iface // To be backfilled
	PredicateTransformer interface{} //nolint:iface // To be backfilled
	SignatureVerifier    interface{} //nolint:iface // To be backfilled
)

type EvalEnginePlugin interface {
	CanRegisterFor(class.Class) bool
	Identity() *class.Identity
}
