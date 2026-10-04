// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/policylabs/ampel/internal/cmd"
)

func main() {
	cmdline := cmd.New()
	if err := cmdline.Execute(); err != nil {
		os.Exit(1)
	}
}
