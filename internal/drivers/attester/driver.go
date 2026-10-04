// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package attester

import (
	"io"

	papi "github.com/carabiner-dev/policy/api/v1"

	"github.com/carabiner-dev/ampel/pkg/attest"
)

func New() *Driver {
	return &Driver{
		Attester: attest.New(),
	}
}

type Driver struct {
	Attester *attest.ResultsAttester
}

func (d *Driver) RenderResultSet(w io.Writer, rset *papi.ResultSet) error {
	return d.Attester.AttestTo(w, rset)
}

func (d *Driver) RenderResult(w io.Writer, status *papi.Result) error {
	return d.Attester.AttestTo(w, status)
}

func (d *Driver) RenderResultGroup(w io.Writer, status *papi.ResultGroup) error {
	return d.Attester.AttestTo(w, status)
}
