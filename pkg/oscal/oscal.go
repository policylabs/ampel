// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package oscal

// Temporary to be switched to go-oscal
type Catalog struct {
	UUID     string   `json:"uuid"`
	Metadata Metadata `json:"metadata"`
	Groups   []Group  `json:"groups"`
}

type Metadata struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type Group struct {
	ID       string    `json:"id"`
	Class    string    `json:"class"`
	Title    string    `json:"title"`
	Controls []Control `json:"controls"`
}

type Control struct {
	ID    string `json:"id"`
	Class string `json:"class"`
	Title string `json:"title"`
}
