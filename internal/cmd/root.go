// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"
	"sigs.k8s.io/release-utils/version"
)

const appname = "ampel"

func AmpelBanner(legend string) string {
	r := color.New(color.FgRed, color.BgBlack).SprintFunc()
	y := color.New(color.FgYellow, color.BgBlack).SprintFunc()
	g := color.New(color.FgGreen, color.BgBlack).SprintFunc()
	w := color.New(color.FgHiWhite, color.BgBlack).SprintFunc()
	w2 := color.New(color.Faint, color.FgWhite, color.BgBlack).SprintFunc()
	if legend != "" {
		legend = w2(": " + legend)
	}
	return fmt.Sprintf("%s%s%s%s%s", r("⬤"), y("⬤"), g("⬤"), w(strings.ToUpper(appname)), legend)
}

var rootCmd = &cobra.Command{
	Short: "A general purpose policy evaluator",
	Long: fmt.Sprintf(`
%s

Ampel is a lightweight, embeddable policy engine that can verify if an
artifact (a subject) complies with a given policy based on attested evidence.

Ampel supports different signature envelopes and while the verifier can run
against any attestation predicate in JSON, known predicates can provide added
functionality for known types. Ampel ships with built in predicates for common
supply chain security technologies such as SBOMs, SLSA, Vulnerability Reports
and VEX.

The policy architecture in ampel is based on Tenets, the principles we want to
check which in turn are turned into Assertions once evidence is provided and
verified.

At present , tenets are written in CEL but ampel is designed to support other
policy languages which can be specified in the policy code.

Policies can define tranformation engines that can mutate any ingested attestations
to normalize or mix data, the transformation results are then exposed to the
evaluation engine.



`, AmpelBanner("Amazing Multipurpose Policy Engine and L")),
	Use:               appname,
	SilenceUsage:      false,
	PersistentPreRunE: initLogging,
}

type commandLineOptions struct {
	logLevel string
}

var commandLineOpts = commandLineOptions{}

// New returns the cobra construct for the CLI tool
func New() *cobra.Command {
	rootCmd.PersistentFlags().StringVar(
		&commandLineOpts.logLevel,
		"log-level",
		"info",
		fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)
	addVerify(rootCmd)
	rootCmd.AddCommand(version.WithFont("doom"))
	return rootCmd
}

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(commandLineOpts.logLevel)
}
