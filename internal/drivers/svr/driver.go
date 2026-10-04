// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package svr

import (
	"io"

	papi "github.com/policylabs/policy/api/v1"

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

func (d *Driver) RenderResultSet(w io.Writer, set *papi.ResultSet) error {
	return d.Attester.AttestTo(w, set, attest.WithFormat("svr"))
}

func (d *Driver) RenderResult(w io.Writer, result *papi.Result) error {
	return d.Attester.AttestTo(w, result, attest.WithFormat("svr"))
}

func (d *Driver) RenderResultGroup(w io.Writer, group *papi.ResultGroup) error {
	return d.Attester.AttestTo(w, group, attest.WithFormat("svr"))
}
