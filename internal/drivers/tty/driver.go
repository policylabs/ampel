// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"fmt"
	"io"

	papi "github.com/policylabs/policy/api/v1"
)

// New returns the TTY driver, wired to the default Decorator.
func New() *Driver {
	return &Driver{Decorator: &Decorator{}}
}

// Driver renders Ampel results as ANSI-styled terminal tables using
// github.com/carabiner-dev/termtable. The tables auto-size to the
// attached terminal and clip overwide output to the screen.
type Driver struct {
	Decorator *Decorator
}

// RenderResultSet writes the 4-column policy-set table to w.
func (d *Driver) RenderResultSet(w io.Writer, rset *papi.ResultSet) error {
	if _, err := d.resultSetTable(rset).WriteTo(w); err != nil {
		return fmt.Errorf("rendering ResultSet table: %w", err)
	}
	return nil
}

// RenderResultGroup writes the 4-column policy-group table to w.
func (d *Driver) RenderResultGroup(w io.Writer, rset *papi.ResultGroup) error {
	if _, err := d.resultGroupTable(rset).WriteTo(w); err != nil {
		return fmt.Errorf("rendering ResultGroup table: %w", err)
	}
	return nil
}

// RenderResult writes the 3-column single-result table to w.
func (d *Driver) RenderResult(w io.Writer, result *papi.Result) error {
	if _, err := d.resultTable(result).WriteTo(w); err != nil {
		return fmt.Errorf("rendering Result table: %w", err)
	}
	return nil
}
