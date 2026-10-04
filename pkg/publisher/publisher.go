// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package publisher emits the results of an AMPEL policy evaluation to external
// systems. The Publisher object aggregates a set of configured emitters (the
// drivers: a webhook, a gRPC API, an eventing system, etc) and fans a single
// PublishResults call out to all of them.
//
// For now, publishing is best effort: PublishResults invokes every emitter but
// never queues, retries or fails because an emitter returned an error. Any
// emitter that needs a retry mechanism implements it itself.
//
// Emitters are pluggable and follow the same registration model as the
// collector's repository drivers: each emitter registers a factory under a
// moniker and is selected through an initstring of the form "moniker:spec". The
// factory receives the spec (everything after the first colon) and parses it
// however the emitter sees fit. The built-in emitters are wired into the
// registry by the publisher/drivers package's LoadDefaultEmitterTypes.
package publisher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	papi "github.com/policylabs/policy/api/v1"
)

// Emitter is the interface implemented by all publisher drivers.
type Emitter interface {
	// Emit sends the evaluation results to the emitter's destination. It is
	// called once per evaluation with the results of the verified policy
	// material. The papi.Results interface is satisfied by all of the material
	// kinds the verifier can produce (*papi.Result, *papi.ResultGroup and
	// *papi.ResultSet). Emit is best-effort: a returned error is logged by the
	// Publisher but never fails the evaluation.
	Emit(context.Context, papi.Results, ...EmitOpt) error
}

// EmitOpt is a functional option modifying a single Emit call.
type EmitOpt func(*EmitOptions)

// EmitOptions carries cross-emitter options for an Emit call. It is currently
// empty but reserved so the Emit signature is stable as options are added.
type EmitOptions struct{}

// EmitterFactory builds a configured emitter from the spec portion of an
// initstring (everything after the "moniker:" prefix). Each emitter parses its
// own spec.
type EmitterFactory func(string) (Emitter, error)

var (
	emitterTypes             = map[string]EmitterFactory{}
	ErrTypeAlreadyRegistered = errors.New("emitter type already registered")
	mtx                      sync.RWMutex
)

// EmitterFromString builds an emitter from an initstring of the form
// "moniker:spec". The string is split on the first colon: the first half
// selects the emitter factory from the registry and the remainder is handed to
// it verbatim.
func EmitterFromString(init string) (Emitter, error) {
	t, init, _ := strings.Cut(init, ":")
	mtx.RLock()
	b, ok := emitterTypes[t]
	mtx.RUnlock()
	if ok {
		return b(init)
	}
	return nil, fmt.Errorf("emitter type unknown: %q", t)
}

// RegisterEmitterType registers a new type of emitter.
func RegisterEmitterType(moniker string, factory EmitterFactory) error {
	mtx.Lock()
	defer mtx.Unlock()
	if _, ok := emitterTypes[moniker]; ok {
		return ErrTypeAlreadyRegistered
	}
	emitterTypes[moniker] = factory
	return nil
}

// UnregisterEmitterType removes an emitter type from the registry.
func UnregisterEmitterType(moniker string) {
	mtx.Lock()
	delete(emitterTypes, moniker)
	mtx.Unlock()
}

// Publisher fans an evaluation's results out to a set of configured emitters.
type Publisher struct {
	Emitters []Emitter

	// inits holds the emitter initstrings queued via AddEmitterInit, built into
	// Emitters by Build once the required emitter types are registered.
	inits []string

	// loadDefaults reports whether the default emitter types should be
	// registered before Build runs. It defaults to true.
	loadDefaults bool
}

// New returns an empty Publisher with default emitter loading enabled.
func New() *Publisher {
	return &Publisher{loadDefaults: true}
}

// AddEmitter adds already-built emitters to the publisher.
func (p *Publisher) AddEmitter(emitters ...Emitter) {
	p.Emitters = append(p.Emitters, emitters...)
}

// AddEmitterInit queues an emitter initstring ("moniker:spec"). The emitter is
// constructed when Build is called, after the required types are registered.
func (p *Publisher) AddEmitterInit(inits ...string) {
	p.inits = append(p.inits, inits...)
}

// SetLoadDefaults controls whether Build expects the default emitter types to
// be registered. It is enabled by default.
func (p *Publisher) SetLoadDefaults(load bool) { p.loadDefaults = load }

// LoadsDefaults reports whether the default emitter types should be registered
// before the queued emitters are built.
func (p *Publisher) LoadsDefaults() bool { return p.loadDefaults }

// Build constructs the queued emitter initstrings into emitters. It must be
// called after the required emitter types are registered (see the
// publisher/drivers package's LoadDefaultEmitterTypes).
func (p *Publisher) Build() error {
	for _, init := range p.inits {
		e, err := EmitterFromString(init)
		if err != nil {
			return fmt.Errorf("building emitter %q: %w", init, err)
		}
		p.Emitters = append(p.Emitters, e)
	}
	p.inits = nil
	return nil
}

// PublishResults emits the results through all configured emitters and returns
// the joined emitter errors. Every emitter is always invoked; a failing one
// does not stop the others. The verifier treats publishing as best-effort and
// ignores the returned error.
func (p *Publisher) PublishResults(ctx context.Context, results papi.Results) error {
	if p == nil || results == nil {
		return nil
	}
	errs := []error{}
	for _, e := range p.Emitters {
		if err := e.Emit(ctx, results); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
