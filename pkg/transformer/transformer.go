// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package transformer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/policylabs/attestation"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/carabiner-dev/ampel/pkg/transformer/protobom"
	"github.com/carabiner-dev/ampel/pkg/transformer/vex"
	"github.com/carabiner-dev/ampel/pkg/transformer/vulnreport"
)

// Ensure the loaded drivers implement the transformers interface
var (
	_ Transformer = (*protobom.Transformer)(nil)
	_ Transformer = (*vulnreport.Transformer)(nil)
	_ Transformer = (*vex.Transformer)(nil)
)

// Factory returns a list of transformers from
// a list of string identifiers
type Factory struct{}

// Get returns a transformer for the given class, initialized with the
// supplied config. Pass nil config when the policy declared none; each
// transformer applies its own defaults.
func (tf *Factory) Get(c Class, config *structpb.Struct) (Transformer, error) {
	if !strings.HasPrefix(c.Name(), "internal:") {
		return nil, errors.New("only internal transformers are supported for now")
	}

	s := strings.TrimPrefix(c.Name(), "internal:")
	var t Transformer
	switch s {
	case protobom.ClassName:
		t = protobom.New()
	case vulnreport.ClassName:
		t = vulnreport.New()
	case vex.ClassName:
		t = vex.New()
	default:
		return nil, fmt.Errorf("unknown transformer %q", s)
	}
	logrus.Debugf("Found driver for transformer class %s", s)
	if err := t.Init(config); err != nil {
		return nil, fmt.Errorf("initializing transformer %q: %w", s, err)
	}
	return t, nil
}

// Transformer is an interface that models a predicate transformer
type Transformer interface {
	// Init configures the transformer from policy-supplied config. Implementations
	// must tolerate a nil config and apply defaults.
	Init(*structpb.Struct) error
	Mutate(attestation.Subject, []attestation.Predicate) (attestation.Subject, []attestation.Predicate, error)
}

type Info struct {
	Identifier string
	Version    string
	Hashes     map[string]string
}

// InputRecord records the inputs that went into a predicate
// transformation process.
type InputRecord struct {
	Type     attestation.PredicateType
	Subjects attestation.Subject
	Hashes   map[string]string
}

// OutputRecord is a struct that catpures metadata about
// the outputs resulting from a tranformer run.
type OutputRecord struct {
	Hashes map[string]string
	Type   attestation.PredicateType
}

// Record is a struct that records a run
// of a transformer.
type Record struct {
	Date        *time.Time
	Transformer Info
	Inputs      []InputRecord
	Output      []OutputRecord
}
