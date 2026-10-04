// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/signer/key"

	"github.com/carabiner-dev/ampel/pkg/oscal"
	"github.com/carabiner-dev/ampel/pkg/publisher"
	publisherdrivers "github.com/carabiner-dev/ampel/pkg/publisher/drivers"
)

var ErrMissingAttestations = errors.New("required attestations missing to verify subject")

// ErrUnverifiedAttestations is returned (wrapped) when evidence was supplied
// but none of it could be admitted because no signature verified: the
// attestations are unsigned, or signed with keys the verifier does not hold.
var ErrUnverifiedAttestations = errors.New("no verified attestations available to evaluate the policy")

type AmpelStatusChecker interface {
	GatherResults(context.Context, *StatusOptions, attestation.Subject) ([]attestation.Envelope, error)
	ParseAttestedResults(context.Context, *StatusOptions, []attestation.Envelope) ([]attestation.Predicate, error)
	CheckIdentities(*StatusOptions, []attestation.Envelope) (bool, error)
	ComputeComplianceStatus(*oscal.Catalog, []attestation.Predicate) (*Status, error)
}

func New(opts ...fnOpt) (*Ampel, error) {
	agent, err := collector.New()
	if err != nil {
		return nil, err
	}
	ampel := &Ampel{
		impl:      &defaultIplementation{},
		checker:   &defaultStatusChecker{},
		Collector: agent,
		publisher: publisher.New(),
	}

	for _, opFn := range opts {
		if err := opFn(ampel); err != nil {
			return nil, err
		}
	}

	// Register the built-in emitter types (unless disabled) before the publisher
	// builds its queued emitters, which look them up by moniker.
	if ampel.publisher.LoadsDefaults() {
		if err := publisherdrivers.LoadDefaultEmitterTypes(); err != nil {
			return nil, fmt.Errorf("loading default emitter types: %w", err)
		}
	}
	if err := ampel.publisher.Build(); err != nil {
		return nil, fmt.Errorf("building publisher: %w", err)
	}

	return ampel, nil
}

type fnOpt func(*Ampel) error

var WithCollector = func(repository attestation.Repository) fnOpt {
	return func(a *Ampel) error {
		return a.Collector.AddRepository(repository)
	}
}

var WithCollectors = func(repos []attestation.Repository) fnOpt {
	return func(a *Ampel) error {
		return a.Collector.AddRepository(repos...)
	}
}

var WithKeys = func(keys ...key.PublicKeyProvider) fnOpt {
	return func(a *Ampel) error {
		a.Collector.AddKeys(keys...)
		return nil
	}
}

// WithCollectorInit adds a collector from an init string
var WithCollectorInit = func(init string) fnOpt {
	return func(ampel *Ampel) error {
		if err := ampel.Collector.AddRepositoryFromString(init); err != nil {
			return err
		}
		return nil
	}
}

// WithCollectorInit adds multiple collectors from a list of init strings
var WithCollectorInits = func(init []string) fnOpt {
	return func(ampel *Ampel) error {
		for _, s := range init {
			if err := ampel.Collector.AddRepositoryFromString(s); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithPublisherInit adds an emitter from an init string ("moniker:spec"). The
// emitter is built when the verifier is created, after the default emitter
// types are registered.
var WithPublisherInit = func(init string) fnOpt {
	return func(ampel *Ampel) error {
		ampel.publisher.AddEmitterInit(init)
		return nil
	}
}

// WithPublisherInits adds multiple emitters from a list of init strings.
var WithPublisherInits = func(init []string) fnOpt {
	return func(ampel *Ampel) error {
		ampel.publisher.AddEmitterInit(init...)
		return nil
	}
}

// WithDefaultPublishers controls whether the built-in emitter types are
// registered when the verifier is created. It is enabled by default; pass false
// to manage the emitter registry yourself.
var WithDefaultPublishers = func(load bool) fnOpt {
	return func(ampel *Ampel) error {
		ampel.publisher.SetLoadDefaults(load)
		return nil
	}
}

// Ampel is the attestation verifier
type Ampel struct {
	impl      AmpelVerifier
	checker   AmpelStatusChecker
	Collector *collector.Agent
	publisher *publisher.Publisher
}
