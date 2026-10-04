// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"errors"
	"reflect"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/policylabs/ampel/pkg/evaluator/plugins/cvss"
)

// OSVType is the CEL receiver type backing the `osv` variable.
var OSVType = cel.ObjectType("osv", traits.ReceiverType)

type OSVTool struct{}

// Functions returns the CEL member functions exposed on the `osv` object.
//
// Document-level take an OSV results object or a whole predicate, so both
// osv.vulns(predicate) and osv.vulns(predicate.data) work:
//
//	osv.vulns(data)             -> list  : every vulnerability, flattened across
//	                                       results -> packages -> vulnerabilities
//	osv.ids(data)               -> list  : the id of every vulnerability
//	osv.forEcosystem(data, eco) -> list  : vulnerabilities in the ecosystem
//	osv.forPackage(data, name)  -> list  : vulnerabilities affecting the package
//
// Vulnerability-level (take a single vulnerability from osv.vulns):
//
//	osv.aliases(vuln)       -> list  : a vulnerability's id plus its aliases
//	osv.matchesID(vuln, id) -> bool  : true if id equals the vuln's id or alias
//	osv.cvss(vuln)          -> double: highest CVSS base score across severities
//	osv.severityLabel(vuln) -> string: qualitative severity (CRITICAL/HIGH/...)
//	osv.isFixed(vuln)       -> bool  : true if a fixed version is available
//	osv.fixedVersions(vuln) -> list  : the versions that fix the vulnerability
//	osv.purl(vuln)          -> string: the affected package URL
//	osv.ecosystem(vuln)     -> string: the affected package ecosystem
//	osv.references(vuln)    -> list  : reference URLs
//
// Enriched field provided by original scanners *stored in database_specific) and
// which default to 0/false/empty when the scanner did not supply the field:
//
//	osv.epss(vuln)  -> double: EPSS exploitation probability (0..1)
//	osv.risk(vuln)  -> double: scanner risk score
//	osv.isKEV(vuln) -> bool  : listed in a known-exploited catalog (CISA KEV)
//	osv.cwes(vuln)  -> list  : associated CWE identifiers
func (t *OSVTool) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		// Document-level
		dynListFn("vulns", flattenVulns),
		stringListFn("ids", vulnIDs),
		dynFilterFn("forEcosystem", forEcosystem),
		dynFilterFn("forPackage", forPackage),

		// Vulnerability-level
		stringListFn("aliases", aliasesOf),
		cel.Function("matchesID",
			cel.MemberOverload("osv_matchesid_binding",
				[]*cel.Type{OSVType, cel.DynType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					if len(args) != 3 {
						return types.NewErrFromString("osv.matchesID requires a vulnerability and an id")
					}
					id, ok := args[2].Value().(string)
					if !ok {
						return types.NewErrFromString("osv.matchesID: id must be a string")
					}
					return types.Bool(slices.Contains(aliasesOf(toGo(args[1])), id))
				}),
			),
		),
		doubleFn("cvss", bestCVSS),
		stringFn("severityLabel", severityLabel),
		boolFn("isFixed", isFixed),
		stringListFn("fixedVersions", fixedVersions),
		stringFn("purl", vulnPURL),
		stringFn("ecosystem", vulnEcosystem),
		stringListFn("references", vulnReferences),

		// Enrichment (from database_specific)
		doubleFn("epss", vulnEPSS),
		doubleFn("risk", vulnRisk),
		boolFn("isKEV", vulnIsKEV),
		stringListFn("cwes", vulnCWEs),
	}
}

// dynListFn registers an (osv, dyn) -> list<dyn> member function.
func dynListFn(name string, fn func(any) []any) cel.EnvOption {
	return cel.Function(name,
		cel.MemberOverload("osv_"+name+"_binding",
			[]*cel.Type{OSVType, cel.DynType}, cel.ListType(cel.DynType),
			cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
				return types.DefaultTypeAdapter.NativeToValue(fn(toGo(rhs)))
			}),
		),
	)
}

// stringListFn registers an (osv, dyn) -> list<string> member function.
func stringListFn(name string, fn func(any) []string) cel.EnvOption {
	return cel.Function(name,
		cel.MemberOverload("osv_"+name+"_binding",
			[]*cel.Type{OSVType, cel.DynType}, cel.ListType(cel.StringType),
			cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
				return types.DefaultTypeAdapter.NativeToValue(fn(toGo(rhs)))
			}),
		),
	)
}

// stringFn registers an (osv, dyn) -> string member function.
func stringFn(name string, fn func(any) string) cel.EnvOption {
	return cel.Function(name,
		cel.MemberOverload("osv_"+name+"_binding",
			[]*cel.Type{OSVType, cel.DynType}, cel.StringType,
			cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
				return types.String(fn(toGo(rhs)))
			}),
		),
	)
}

// boolFn registers an (osv, dyn) -> bool member function.
func boolFn(name string, fn func(any) bool) cel.EnvOption {
	return cel.Function(name,
		cel.MemberOverload("osv_"+name+"_binding",
			[]*cel.Type{OSVType, cel.DynType}, cel.BoolType,
			cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
				return types.Bool(fn(toGo(rhs)))
			}),
		),
	)
}

// doubleFn registers an (osv, dyn) -> double member function.
func doubleFn(name string, fn func(any) float64) cel.EnvOption {
	return cel.Function(name,
		cel.MemberOverload("osv_"+name+"_binding",
			[]*cel.Type{OSVType, cel.DynType}, cel.DoubleType,
			cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
				return types.Double(fn(toGo(rhs)))
			}),
		),
	)
}

// dynFilterFn registers an (osv, dyn, string) -> list<dyn> member function used
// by the document-level filters (forEcosystem, forPackage).
func dynFilterFn(name string, fn func(any, string) []any) cel.EnvOption {
	return cel.Function(name,
		cel.MemberOverload("osv_"+name+"_binding",
			[]*cel.Type{OSVType, cel.DynType, cel.StringType}, cel.ListType(cel.DynType),
			cel.FunctionBinding(func(args ...ref.Val) ref.Val {
				if len(args) != 3 {
					return types.NewErrFromString("osv." + name + " requires data and a string argument")
				}
				arg, ok := args[2].Value().(string)
				if !ok {
					return types.NewErrFromString("osv." + name + ": second argument must be a string")
				}
				return types.DefaultTypeAdapter.NativeToValue(fn(toGo(args[1]), arg))
			}),
		),
	)
}

// OSV traversal (operates on the native JSON shape produced by protojson).

// osvResults returns the OSV results object, unwrapping a predicate `data` key
// when present so callers may pass either a predicate or its data.
func osvResults(data any) map[string]any {
	m, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	if _, ok := m["results"]; ok {
		return m
	}
	if inner, ok := m["data"].(map[string]any); ok {
		if _, ok := inner["results"]; ok {
			return inner
		}
	}
	return nil
}

// flattenVulns collapses results -> packages -> vulnerabilities into one list.
func flattenVulns(data any) []any {
	out := []any{}
	root := osvResults(data)
	if root == nil {
		return out
	}
	results, ok := root["results"].([]any)
	if !ok {
		return out
	}
	for _, r := range results {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		packages, ok := rm["packages"].([]any)
		if !ok {
			continue
		}
		for _, p := range packages {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			if vulns, ok := pm["vulnerabilities"].([]any); ok {
				out = append(out, vulns...)
			}
		}
	}
	return out
}

// vulnIDs returns the id of every vulnerability in the document.
func vulnIDs(data any) []string {
	out := []string{}
	for _, v := range flattenVulns(data) {
		if vm, ok := v.(map[string]any); ok {
			if id, ok := vm["id"].(string); ok && id != "" {
				out = append(out, id)
			}
		}
	}
	return out
}

// aliasesOf returns a vulnerability's id followed by its declared aliases.
func aliasesOf(vuln any) []string {
	out := []string{}
	vm, ok := vuln.(map[string]any)
	if !ok {
		return out
	}
	if id, ok := vm["id"].(string); ok && id != "" {
		out = append(out, id)
	}
	if aliases, ok := vm["aliases"].([]any); ok {
		for _, a := range aliases {
			if s, ok := a.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// bestVector returns the severity vector with the highest CVSS score, or "".
func bestVector(vuln any) string {
	vm, ok := vuln.(map[string]any)
	if !ok {
		return ""
	}
	severities, ok := vm["severity"].([]any)
	if !ok {
		return ""
	}
	best := ""
	bestScore := -1.0
	for _, s := range severities {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		vector, ok := sm["score"].(string)
		if !ok || vector == "" {
			continue
		}
		if score, err := cvss.Score(vector); err == nil && score > bestScore {
			bestScore = score
			best = vector
		}
	}
	return best
}

// bestCVSS returns the highest CVSS base score across the vulnerability's
// severity vectors, or 0 when none are present or parseable.
func bestCVSS(vuln any) float64 {
	vector := bestVector(vuln)
	if vector == "" {
		return 0
	}
	if score, err := cvss.Score(vector); err == nil {
		return score
	}
	return 0
}

// severityLabel returns a qualitative severity: the CVSS rating of the highest
// scoring vector, falling back to the scanner's own label in database_specific
// (upper-cased) for vulnerabilities that carry no CVSS vector.
func severityLabel(vuln any) string {
	if vector := bestVector(vuln); vector != "" {
		if severity, err := cvss.Severity(vector); err == nil && severity != "" {
			return severity
		}
	}
	if s := dbSpecificSeverity(vuln); s != "" {
		return strings.ToUpper(s)
	}
	return ""
}

// dbSpecificSeverity returns the scanner-provided severity label stored in the
// vulnerability's database_specific block, if any.
func dbSpecificSeverity(vuln any) string {
	vm, ok := vuln.(map[string]any)
	if !ok {
		return ""
	}
	db, ok := vm["database_specific"].(map[string]any)
	if !ok {
		return ""
	}
	if s, ok := db["severity"].(string); ok {
		return s
	}
	return ""
}

// fixedVersions returns every version that fixes the vulnerability, drawn from
// the affected ranges' "fixed" events.
func fixedVersions(vuln any) []string {
	out := []string{}
	vm, ok := vuln.(map[string]any)
	if !ok {
		return out
	}
	affected, ok := vm["affected"].([]any)
	if !ok {
		return out
	}
	for _, a := range affected {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		ranges, ok := am["ranges"].([]any)
		if !ok {
			continue
		}
		for _, r := range ranges {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			events, ok := rm["events"].([]any)
			if !ok {
				continue
			}
			for _, e := range events {
				em, ok := e.(map[string]any)
				if !ok {
					continue
				}
				if fixed, ok := em["fixed"].(string); ok && fixed != "" {
					out = append(out, fixed)
				}
			}
		}
	}
	return out
}

// isFixed reports whether the vulnerability has at least one fixed version.
func isFixed(vuln any) bool {
	return len(fixedVersions(vuln)) > 0
}

// affectedPackageField returns the first non-empty value of the named field
// across the vulnerability's affected packages.
func affectedPackageField(vuln any, field string) string {
	vm, ok := vuln.(map[string]any)
	if !ok {
		return ""
	}
	affected, ok := vm["affected"].([]any)
	if !ok {
		return ""
	}
	for _, a := range affected {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		pkg, ok := am["package"].(map[string]any)
		if !ok {
			continue
		}
		if v, ok := pkg[field].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func vulnPURL(vuln any) string      { return affectedPackageField(vuln, "purl") }
func vulnEcosystem(vuln any) string { return affectedPackageField(vuln, "ecosystem") }

// forEcosystem returns the vulnerabilities whose affected package is in the
// given OSV ecosystem (matched case-insensitively).
func forEcosystem(data any, ecosystem string) []any {
	out := []any{}
	for _, v := range flattenVulns(data) {
		if strings.EqualFold(vulnEcosystem(v), ecosystem) {
			out = append(out, v)
		}
	}
	return out
}

// forPackage returns the vulnerabilities affecting the given package, matched
// by exact package name or PURL, or by the query appearing within the PURL (so
// a bare package name matches its versioned PURL).
func forPackage(data any, pkg string) []any {
	out := []any{}
	for _, v := range flattenVulns(data) {
		name := affectedPackageField(v, "name")
		purl := vulnPURL(v)
		if name == pkg || purl == pkg || (pkg != "" && strings.Contains(purl, pkg)) {
			out = append(out, v)
		}
	}
	return out
}

// toGo converts a CEL value (a structpb-backed map/list from predicate data)
// into native Go values (map[string]any / []any / primitives).
func toGo(v ref.Val) any {
	if v == nil {
		return nil
	}
	if native, err := v.ConvertToNative(reflect.TypeFor[*structpb.Value]()); err == nil {
		if sv, ok := native.(*structpb.Value); ok {
			return sv.AsInterface()
		}
	}
	// ampel's CEL predicate wrapper cannot convert to a native map but exposes
	// its fields via indexing; pull out the OSV data so osv.vulns(predicate)
	// works the same as osv.vulns(predicate.data).
	if indexer, ok := v.(traits.Indexer); ok {
		if data := indexer.Get(types.String("data")); data != nil && !types.IsError(data) {
			return toGo(data)
		}
	}
	return v.Value()
}

// vulnReferences returns the URLs of the vulnerability's references.
func vulnReferences(vuln any) []string {
	out := []string{}
	vm, ok := vuln.(map[string]any)
	if !ok {
		return out
	}
	refs, ok := vm["references"].([]any)
	if !ok {
		return out
	}
	for _, r := range refs {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if url, ok := rm["url"].(string); ok && url != "" {
			out = append(out, url)
		}
	}
	return out
}

// dbSpecific returns the vulnerability's database_specific object, or nil.
func dbSpecific(vuln any) map[string]any {
	vm, ok := vuln.(map[string]any)
	if !ok {
		return nil
	}
	if db, ok := vm["database_specific"].(map[string]any); ok {
		return db
	}
	return nil
}

// vulnEPSS returns the EPSS probability from database_specific. It accepts
// either a bare number or a list of EPSS records (scanner-dependent shape),
// returning the first record's score in the latter case.
func vulnEPSS(vuln any) float64 {
	db := dbSpecific(vuln)
	if db == nil {
		return 0
	}
	switch v := db["epss"].(type) {
	case float64:
		return v
	case []any:
		if len(v) > 0 {
			if m, ok := v[0].(map[string]any); ok {
				if f, ok := m["epss"].(float64); ok {
					return f
				}
			}
		}
	}
	return 0
}

// vulnRisk returns the scanner-provided risk score from database_specific.
func vulnRisk(vuln any) float64 {
	if db := dbSpecific(vuln); db != nil {
		if f, ok := db["risk"].(float64); ok {
			return f
		}
	}
	return 0
}

// vulnIsKEV reports whether the vulnerability is flagged as known-exploited in
// database_specific.
func vulnIsKEV(vuln any) bool {
	if db := dbSpecific(vuln); db != nil {
		if b, ok := db["known_exploited"].(bool); ok {
			return b
		}
	}
	return false
}

// vulnCWEs returns the CWE identifiers stored in database_specific.
func vulnCWEs(vuln any) []string {
	out := []string{}
	db := dbSpecific(vuln)
	if db == nil {
		return out
	}
	if list, ok := db["cwe_ids"].([]any); ok {
		for _, c := range list {
			if s, ok := c.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// CEL ref.Val + Library plumbing.

func (t *OSVTool) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal == types.TypeType {
		return OSVType
	}
	return types.NewErr("type conversion not allowed for osv")
}

func (*OSVTool) Type() ref.Type { return OSVType }

func (*OSVTool) Equal(_ ref.Val) ref.Val {
	return types.NewErr("objects cannot be compared")
}

func (t *OSVTool) Value() any { return t }

func (*OSVTool) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("osv cannot be converted to native")
}

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	if val, ok := value.(OSVTool); ok {
		return &val
	}
	return types.DefaultTypeAdapter.NativeToValue(value)
}

func (t *OSVTool) CompileOptions() []cel.EnvOption {
	funcs := t.Functions()
	ret := make([]cel.EnvOption, 0, 3+len(funcs))
	ret = append(ret,
		cel.Types(OSVType),
		cel.CustomTypeAdapter(&TypeAdapter{}),
		cel.Variable("osv", OSVType),
	)
	ret = append(ret, funcs...)
	return ret
}

func (*OSVTool) ProgramOptions() []cel.ProgramOption { return nil }
