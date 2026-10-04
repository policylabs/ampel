// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package stdout implements a mock emitter that writes the evaluation results
// as JSON to a writer (os.Stdout by default). It is mainly useful for tests and
// for manually inspecting what would be published. It is not wired into
// LoadDefaultEmitterTypes; tests that need it register it explicitly.
package stdout

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	papi "github.com/policylabs/policy/api/v1"

	"github.com/carabiner-dev/ampel/pkg/publisher"
)

// TypeMoniker is the moniker used to select this emitter in an initstring.
const TypeMoniker = "stdout"

// Build constructs a stdout emitter. The init string is ignored; results are
// written to os.Stdout.
func Build(string) (publisher.Emitter, error) {
	return New(), nil
}

// Emitter writes the results as indented JSON to Writer.
type Emitter struct {
	Writer io.Writer
}

// New returns a stdout emitter writing to os.Stdout.
func New() *Emitter {
	return &Emitter{Writer: os.Stdout}
}

// Emit writes the results to the configured writer as indented JSON.
func (e *Emitter) Emit(_ context.Context, results papi.Results, _ ...publisher.EmitOpt) error {
	w := e.Writer
	if w == nil {
		w = os.Stdout
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}
	if _, err := fmt.Fprintln(w, string(data)); err != nil {
		return fmt.Errorf("writing results: %w", err)
	}
	return nil
}
