// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package markdown

import (
	"fmt"
	"io"

	papi "github.com/carabiner-dev/policy/api/v1"

	"github.com/carabiner-dev/ampel/internal/drivers/gotable"
)

func New() *Driver {
	return &Driver{
		TableWriter: gotable.TableBuilder{
			Decorator: &Decorator{},
		},
	}
}

type Driver struct {
	TableWriter gotable.TableBuilder
}

// RenderResultSet takes a resultset
func (d *Driver) RenderResultSet(w io.Writer, rset *papi.ResultSet) error {
	for _, result := range rset.GetResults() {
		t, err := d.TableWriter.ResultsTable(result)
		if err != nil {
			return fmt.Errorf("building table: %w", err)
		}

		t.SetOutputMirror(w)
		t.RenderMarkdown()
	}
	for _, grp := range rset.GetGroups() {
		t, err := d.TableWriter.ResultGroupTable(grp)
		if err != nil {
			return fmt.Errorf("building group table: %w", err)
		}

		t.SetOutputMirror(w)
		t.RenderMarkdown()
	}
	return nil
}

func (d *Driver) RenderResult(w io.Writer, result *papi.Result) error {
	t, err := d.TableWriter.ResultsTable(result)
	if err != nil {
		return fmt.Errorf("building table: %w", err)
	}
	t.SetOutputMirror(w)
	t.RenderMarkdown()
	return nil
}

func (d *Driver) RenderResultGroup(w io.Writer, result *papi.ResultGroup) error {
	t, err := d.TableWriter.ResultGroupTable(result)
	if err != nil {
		return fmt.Errorf("building table: %w", err)
	}
	t.SetOutputMirror(w)
	t.RenderMarkdown()
	return nil
}
