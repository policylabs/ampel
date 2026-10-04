// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package drivers wires the built-in emitter drivers into the publisher
// registry. It is kept separate from the publisher package so that the emitter
// packages can import the publisher interface without creating an import cycle
// (mirroring how the collector keeps its repository drivers separate).
package drivers

import (
	"errors"

	"github.com/carabiner-dev/ampel/pkg/publisher"
	"github.com/carabiner-dev/ampel/pkg/publisher/webhook"
)

// LoadDefaultEmitterTypes loads the default emitter types into the registry to
// get them ready for instantiation. It is idempotent: types that are already
// registered are skipped.
func LoadDefaultEmitterTypes() error {
	errs := []error{}
	for t, factory := range map[string]publisher.EmitterFactory{
		webhook.TypeMoniker: webhook.Build,
	} {
		if err := publisher.RegisterEmitterType(t, factory); err != nil {
			if !errors.Is(err, publisher.ErrTypeAlreadyRegistered) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
