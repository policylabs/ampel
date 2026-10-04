// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package html

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	papi "github.com/policylabs/policy/api/v1"

	"github.com/policylabs/ampel/internal/drivers/gotable"
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
	t, err := d.TableWriter.ResultSetTable(rset)
	if err != nil {
		return fmt.Errorf("building table: %w", err)
	}

	t.SetOutputMirror(w)
	t.Style().HTML = table.HTMLOptions{
		EscapeText: false,
	}
	t.RenderHTML()
	return nil
}

func (d *Driver) RenderResult(w io.Writer, result *papi.Result) error {
	t, err := d.TableWriter.ResultsTable(result)
	if err != nil {
		return fmt.Errorf("building table: %w", err)
	}
	t.SetOutputMirror(w)
	t.Style().HTML = table.HTMLOptions{
		EscapeText: false,
	}
	t.RenderHTML()
	return nil
}

func (d *Driver) RenderResultGroup(w io.Writer, result *papi.ResultGroup) error {
	t, err := d.TableWriter.ResultGroupTable(result)
	if err != nil {
		return fmt.Errorf("building table: %w", err)
	}
	t.SetOutputMirror(w)
	t.Style().HTML = table.HTMLOptions{
		EscapeText: false,
	}
	t.RenderHTML()
	return nil
}
