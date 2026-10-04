// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/predicate/cyclonedx"
	"github.com/policylabs/collector/predicate/generic"
	"github.com/policylabs/collector/predicate/protobom"
	"github.com/policylabs/collector/predicate/spdx"
	"github.com/policylabs/collector/predicate/spdx3"
	"github.com/protobom/protobom/pkg/reader"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

type Transformer struct{}

var ClassName = "protobom"

func New() *Transformer {
	return &Transformer{}
}

// Init satisfies the transformer interface. The protobom transformer takes no config.
func (p *Transformer) Init(_ *structpb.Struct) error {
	return nil
}

// PredicateTypes lists the SBOM predicate types protobom's reader can parse
// into a document.
var PredicateTypes = []attestation.PredicateType{
	spdx.PredicateType,
	spdx3.PredicateType,
	cyclonedx.PredicateType,
}

// Transformer generates a protobom predicate from any of the supported SBOM
// formats.
func (p *Transformer) Mutate(_ attestation.Subject, preds []attestation.Predicate) (attestation.Subject, []attestation.Predicate, error) {
	r := reader.New()
	if len(preds) != 1 {
		return nil, nil, fmt.Errorf("default tranformation requires exactly one predicate")
	}

	if !slices.Contains(PredicateTypes, preds[0].GetType()) {
		return nil, nil, fmt.Errorf(
			"predicate type not supported, must be one of %v (got %s)",
			PredicateTypes, preds[0].GetType(),
		)
	}

	s := bytes.NewReader(preds[0].GetData())
	doc, err := r.ParseStream(s)
	if err != nil {
		// If it's not a supported SBOM format, catch the error and
		// return the common error to hand off to another predicate parser.
		if strings.Contains(err.Error(), "unknown SBOM format") {
			return nil, nil, attestation.ErrNotCorrectFormat
		}
		return nil, nil, fmt.Errorf("parsing data: %w", err)
	}
	bdata, err := protojson.Marshal(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling rendered protobom predicate: %w", err)
	}
	// Reset the new predicates
	return nil, []attestation.Predicate{
		&generic.Predicate{
			Type:   protobom.PredicateType,
			Data:   bdata,
			Parsed: doc,
		},
	}, err
}
