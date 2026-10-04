// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const flagGroupAnnotation = "ampel_group"

// flagGroup is a topical bucket of flags rendered under its own heading
// in --help. Groups are ordered by their position in the slice passed to
// registerFlagGroups; empty groups are skipped at render time.
type flagGroup struct {
	ID    string
	Title string
}

// commandGroups holds the per-command ordered group list consulted by
// the custom usage template. Keyed by *cobra.Command, populated by
// registerFlagGroups and read by groupedFlagUsages. A global map fits
// here because cobra commands are constructed once at startup.
var commandGroups = map[*cobra.Command][]flagGroup{}

// registerFlagGroups records the ordered group list for cmd. Flags
// without a recognized group fall through to the trailing "Other Flags:"
// section.
func registerFlagGroups(cmd *cobra.Command, groups ...flagGroup) {
	commandGroups[cmd] = groups
}

// groupFlags tags each named persistent flag on cmd with group. Unknown
// flag names are skipped silently so the helper stays robust if a flag
// is later renamed or removed.
func groupFlags(cmd *cobra.Command, group string, names ...string) {
	for _, name := range names {
		f := cmd.PersistentFlags().Lookup(name)
		if f == nil {
			continue
		}
		if f.Annotations == nil {
			f.Annotations = map[string][]string{}
		}
		f.Annotations[flagGroupAnnotation] = []string{group}
	}
}

// groupFlagsByPrefix tags every persistent flag on cmd whose name starts
// with one of the given prefixes. Used for flags registered by an
// external library (e.g. signer's *options.SignerSet) where in-place
// annotation at registration isn't possible.
func groupFlagsByPrefix(cmd *cobra.Command, group string, prefixes ...string) {
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		for _, p := range prefixes {
			if strings.HasPrefix(f.Name, p) {
				if f.Annotations == nil {
					f.Annotations = map[string][]string{}
				}
				f.Annotations[flagGroupAnnotation] = []string{group}
				return
			}
		}
	})
}

// groupedFlagUsages renders cmd's local flags bucketed under the group
// headings registered for cmd. Mirrors pflag.FlagSet.FlagUsages output
// per bucket so column alignment matches cobra's default rendering.
func groupedFlagUsages(cmd *cobra.Command) string {
	groups, ok := commandGroups[cmd]
	if !ok || len(groups) == 0 {
		return cmd.LocalFlags().FlagUsages()
	}

	type bucket struct {
		title string
		fs    *pflag.FlagSet
	}
	buckets := make(map[string]*bucket, len(groups))
	for _, g := range groups {
		buckets[g.ID] = &bucket{
			title: g.Title,
			fs:    pflag.NewFlagSet(g.ID, pflag.ContinueOnError),
		}
	}
	other := pflag.NewFlagSet("other", pflag.ContinueOnError)

	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		if vals, ok := f.Annotations[flagGroupAnnotation]; ok && len(vals) > 0 {
			if b, ok := buckets[vals[0]]; ok {
				b.fs.AddFlag(f)
				return
			}
		}
		other.AddFlag(f)
	})

	var sb strings.Builder
	first := true
	emit := func(title string, fs *pflag.FlagSet) {
		if !fs.HasFlags() {
			return
		}
		if !first {
			sb.WriteString("\n")
		}
		first = false
		sb.WriteString(title)
		sb.WriteString("\n")
		sb.WriteString(fs.FlagUsages())
	}
	for _, g := range groups {
		emit(g.Title, buckets[g.ID].fs)
	}
	emit("Other Flags:", other)
	return strings.TrimRight(sb.String(), "\n")
}

func init() {
	cobra.AddTemplateFunc("groupedFlagUsages", groupedFlagUsages)
}

// usageTemplate is cobra's default usage template with the single
// "Flags:" block swapped for a {{groupedFlagUsages .}} call, so flags
// render under topical headings instead of one undifferentiated list.
// The rest of the template (Usage, Aliases, Examples, subcommand
// groups, Global Flags, Additional help topics) is unchanged.
const usageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{groupedFlagUsages . | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command]{{if .HasAvailableInheritedFlags}} [--help]{{end}}" for more information about a command.{{end}}
`

// applyFlagGroupTemplate installs the grouped-flags usage template on
// cmd. Call after flags and groups are registered.
func applyFlagGroupTemplate(cmd *cobra.Command) {
	cmd.SetUsageTemplate(usageTemplate)
}
