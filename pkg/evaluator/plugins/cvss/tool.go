// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cvss

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

type cvssDoc interface {
	Get(abv string) (string, error)
}

type cvssResult struct {
	doc      cvssDoc
	version  string
	score    float64
	severity string
	metrics  []string
}

type CvssTool struct{}

const (
	Version20 = "2.0"
	Version30 = "3.0"
	Version31 = "3.1"
	Version40 = "4.0"

	Prefix30 = "CVSS:3.0/"
	Prefix31 = "CVSS:3.1/"
	Prefix40 = "CVSS:4.0/"

	severityHigh = "HIGH"
	keyVersion   = "version"
	keySeverity  = "severity"
)

var CvssType = cel.ObjectType("cvss", traits.ReceiverType)

var (
	metrics20 = []string{
		"AV", "AC", "Au", "C", "I", "A",
		"E", "RL", "RC",
		"CDP", "TD", "CR", "IR", "AR",
	}
	metrics3x = []string{
		"AV", "AC", "PR", "UI", "S", "C", "I", "A",
		"E", "RL", "RC",
		"CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
	}
	metrics40 = []string{
		"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
		"E",
		"CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
		"S", "AU", "R", "V", "RE", "U",
	}
)

func getCVSSResult(vector string) (*cvssResult, error) {
	switch {
	case strings.HasPrefix(vector, Prefix40):
		doc, err := gocvss40.ParseVector(vector)
		if err != nil {
			return nil, err
		}
		score := doc.Score()
		sev, _ := gocvss40.Rating(score) //nolint:errcheck
		return &cvssResult{doc: doc, version: Version40, score: score, severity: sev, metrics: metrics40}, nil
	case strings.HasPrefix(vector, Prefix31):
		doc, err := gocvss31.ParseVector(vector)
		if err != nil {
			return nil, err
		}
		score := doc.BaseScore()
		sev, _ := gocvss31.Rating(score) //nolint:errcheck
		return &cvssResult{doc: doc, version: Version31, score: score, severity: sev, metrics: metrics3x}, nil
	case strings.HasPrefix(vector, Prefix30):
		doc, err := gocvss30.ParseVector(vector)
		if err != nil {
			return nil, err
		}
		score := doc.BaseScore()
		sev, _ := gocvss30.Rating(score) //nolint:errcheck
		return &cvssResult{doc: doc, version: Version30, score: score, severity: sev, metrics: metrics3x}, nil
	default:
		doc, err := gocvss20.ParseVector(vector)
		if err != nil {
			return nil, fmt.Errorf("unrecognised CVSS vector: %w", err)
		}
		score := doc.BaseScore()
		return &cvssResult{doc: doc, version: Version20, score: score, severity: rating20(score), metrics: metrics20}, nil
	}
}

// Score parses a CVSS vector string and returns its numeric (base) score. It is
// exported so sibling plugins (e.g. osv) can reuse the version-aware scoring
// without duplicating the parsing logic.
func Score(vector string) (float64, error) {
	res, err := getCVSSResult(vector)
	if err != nil {
		return 0, err
	}
	return res.score, nil
}

// Severity parses a CVSS vector string and returns its qualitative rating
// (CRITICAL/HIGH/MEDIUM/LOW/NONE). Exported for reuse by sibling plugins.
func Severity(vector string) (string, error) {
	res, err := getCVSSResult(vector)
	if err != nil {
		return "", err
	}
	return res.severity, nil
}

func rating20(score float64) string {
	switch {
	case score >= 7.0:
		return severityHigh
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func (ct *CvssTool) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		memberDoubleFn("score", func(v string) (float64, error) {
			res, err := getCVSSResult(v)
			if err != nil {
				return 0, err
			}
			return res.score, nil
		}),
		memberStringFn(keySeverity, func(v string) (string, error) {
			res, err := getCVSSResult(v)
			if err != nil {
				return "", err
			}
			return res.severity, nil
		}),
		memberStringFn(keyVersion, func(v string) (string, error) {
			res, err := getCVSSResult(v)
			if err != nil {
				return "", err
			}
			return res.version, nil
		}),
		memberBoolFn("isValid", func(v string) (bool, error) {
			_, err := getCVSSResult(v)
			return err == nil, nil
		}),

		cel.Function("get",
			cel.MemberOverload("cvss_get_binding",
				[]*cel.Type{CvssType, cel.StringType, cel.StringType}, cel.StringType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					if len(args) != 3 {
						return types.NewErrFromString("cvss.get requires a vector and an abbreviation")
					}
					vector, err := asString(args[1], "vector")
					if err != nil {
						return types.NewErrFromString(err.Error())
					}
					abv, err := asString(args[2], "abbreviation")
					if err != nil {
						return types.NewErrFromString(err.Error())
					}
					res, err := getCVSSResult(vector)
					if err != nil {
						return types.NewErrFromString(err.Error())
					}
					val, err := res.doc.Get(abv)
					if err != nil {
						return types.NewErrFromString(
							fmt.Sprintf("metric %s not defined for CVSS %s", abv, res.version),
						)
					}
					return types.String(val)
				}),
			),
		),

		cel.Function("parse",
			cel.MemberOverload("cvss_parse_binding",
				[]*cel.Type{CvssType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
					vector, err := asString(rhs, "vector")
					if err != nil {
						return types.NewErrFromString(err.Error())
					}
					res, err := getCVSSResult(vector)
					if err != nil {
						return types.NewErrFromString(err.Error())
					}
					m := map[string]any{
						keyVersion:  res.version,
						"score":     res.score,
						keySeverity: res.severity,
					}
					for _, abv := range res.metrics {
						if val, getErr := res.doc.Get(abv); getErr == nil {
							m[abv] = val
						}
					}
					reg, regErr := types.NewRegistry()
					if regErr != nil {
						return types.NewErrFromString(regErr.Error())
					}
					return types.NewDynamicMap(reg, m)
				}),
			),
		),

		// Base metrics (all versions)
		namedAccessor("attackVector", "AV"),
		namedAccessor("attackComplexity", "AC"),
		// v2.0 base
		namedAccessor("authentication", "Au", Version20),
		// v3.x base — "S" = Scope; restricted so v4.0 Safety (also "S") is not returned
		namedAccessor("scope", "S", Version30, Version31),
		// C/I/A exist in 2.0 and 3.x, whereas 4.0 uses VC/VI/VA and SC/SI/SA
		namedAccessor("confidentiality", "C", Version20, Version30, Version31),
		namedAccessor("integrity", "I", Version20, Version30, Version31),
		namedAccessor("availability", "A", Version20, Version30, Version31),
		// v3.x / v4.0 base
		namedAccessor("privilegesRequired", "PR", Version30, Version31, Version40),
		namedAccessor("userInteraction", "UI", Version30, Version31, Version40),
		// v4.0 base
		namedAccessor("attackRequirements", "AT", Version40),
		namedAccessor("vulnConfidentiality", "VC", Version40),
		namedAccessor("vulnIntegrity", "VI", Version40),
		namedAccessor("vulnAvailability", "VA", Version40),
		namedAccessor("subConfidentiality", "SC", Version40),
		namedAccessor("subIntegrity", "SI", Version40),
		namedAccessor("subAvailability", "SA", Version40),

		// Temporal / Threat
		// "E" has different value enumerations per version; restrict each alias.
		namedAccessor("exploitability", "E", Version20),
		namedAccessor("exploitMaturity", "E", Version30, Version31, Version40),
		namedAccessor("remediationLevel", "RL", Version20, Version30, Version31),
		namedAccessor("reportConfidence", "RC", Version20, Version30, Version31),

		// Environmental
		// all versions
		namedAccessor("confidentialityRequirement", "CR"),
		namedAccessor("integrityRequirement", "IR"),
		namedAccessor("availabilityRequirement", "AR"),
		// Modified base (v2.0 only)
		namedAccessor("collateralDamagePotential", "CDP", Version20),
		namedAccessor("targetDistribution", "TD", Version20),
		// Modified base (v3.x only)
		namedAccessor("modifiedScope", "MS", Version30, Version31),
		namedAccessor("modifiedConfidentiality", "MC", Version30, Version31),
		namedAccessor("modifiedIntegrity", "MI", Version30, Version31),
		namedAccessor("modifiedAvailability", "MA", Version30, Version31),
		// Modified base (v3.x and v4.0)
		namedAccessor("modifiedAttackVector", "MAV", Version30, Version31, Version40),
		namedAccessor("modifiedAttackComplexity", "MAC", Version30, Version31, Version40),
		namedAccessor("modifiedPrivilegesRequired", "MPR", Version30, Version31, Version40),
		namedAccessor("modifiedUserInteraction", "MUI", Version30, Version31, Version40),
		// Modified base (v4.0 only)
		namedAccessor("modifiedAttackRequirements", "MAT", Version40),
		namedAccessor("modifiedVulnConfidentiality", "MVC", Version40),
		namedAccessor("modifiedVulnIntegrity", "MVI", Version40),
		namedAccessor("modifiedVulnAvailability", "MVA", Version40),
		namedAccessor("modifiedSubConfidentiality", "MSC", Version40),
		namedAccessor("modifiedSubIntegrity", "MSI", Version40),
		namedAccessor("modifiedSubAvailability", "MSA", Version40),

		// Supplemental (v4.0 only)
		// "S" = Safety in v4.0; restricted so v3.x Scope is not returned
		namedAccessor("safety", "S", Version40),
		namedAccessor("automatable", "AU", Version40),
		namedAccessor("recovery", "R", Version40),
		namedAccessor("valueDensity", "V", Version40),
		namedAccessor("vulnerabilityResponseEffort", "RE", Version40),
		namedAccessor("urgency", "U", Version40),
	}
}

// CEL function helpers

func memberFn[T any](name string, celRetType *cel.Type, toVal func(T) ref.Val, fn func(string) (T, error)) cel.EnvOption {
	return cel.Function(name,
		cel.MemberOverload("cvss_"+name+"_binding",
			[]*cel.Type{CvssType, cel.StringType}, celRetType,
			cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
				s, err := asString(rhs, name)
				if err != nil {
					return types.NewErrFromString(err.Error())
				}
				v, err := fn(s)
				if err != nil {
					return types.NewErrFromString(err.Error())
				}
				return toVal(v)
			}),
		),
	)
}

func memberDoubleFn(name string, fn func(string) (float64, error)) cel.EnvOption {
	return memberFn(name, cel.DoubleType, func(v float64) ref.Val { return types.Double(v) }, fn)
}

func memberStringFn(name string, fn func(string) (string, error)) cel.EnvOption {
	return memberFn(name, cel.StringType, func(v string) ref.Val { return types.String(v) }, fn)
}

func memberBoolFn(name string, fn func(string) (bool, error)) cel.EnvOption {
	return memberFn(name, cel.BoolType, func(v bool) ref.Val { return types.Bool(v) }, fn)
}

// namedAccessor creates a (CvssType, string) → string function that looks up
// the metric identified by abv. Returns "" when the metric is not defined in
// the vector's version so policies can safely call any accessor regardless of
// version. When versions is non-empty the accessor also returns "" for vectors
// whose version is not listed, preventing abbreviation clashes (e.g. "S" means
// Scope in v3.x and Safety in v4.0).
func namedAccessor(funcName, abv string, versions ...string) cel.EnvOption {
	return cel.Function(funcName,
		cel.MemberOverload("cvss_"+funcName+"_binding",
			[]*cel.Type{CvssType, cel.StringType}, cel.StringType,
			cel.BinaryBinding(func(_ ref.Val, rhs ref.Val) ref.Val {
				s, err := asString(rhs, funcName)
				if err != nil {
					return types.NewErrFromString(err.Error())
				}
				res, err := getCVSSResult(s)
				if err != nil {
					return types.NewErrFromString(err.Error())
				}
				if len(versions) > 0 && !versionOneOf(res.version, versions) {
					return types.String("")
				}
				val, err := res.doc.Get(abv)
				if err != nil {
					return types.String("")
				}
				return types.String(val)
			}),
		),
	)
}

func versionOneOf(version string, allowed []string) bool {
	for _, v := range allowed {
		if version == v {
			return true
		}
	}
	return false
}

func asString(v ref.Val, slot string) (string, error) {
	s, ok := v.Value().(string)
	if !ok {
		return "", errors.New("expected string for " + slot)
	}
	return s, nil
}

func (ct *CvssTool) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal == types.TypeType {
		return CvssType
	}
	return types.NewErr("type conversion not allowed for cvss")
}

func (*CvssTool) Type() ref.Type {
	return CvssType
}

func (*CvssTool) Equal(_ ref.Val) ref.Val {
	return types.NewErr("objects cannot be compared")
}

func (ct *CvssTool) Value() any {
	return ct
}

func (*CvssTool) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("cvss cannot be converted to native")
}

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	if val, ok := value.(CvssTool); ok {
		return &val
	}
	return types.DefaultTypeAdapter.NativeToValue(value)
}

func (ct *CvssTool) CompileOptions() []cel.EnvOption {
	funcs := ct.Functions()
	ret := make([]cel.EnvOption, 0, 3+len(funcs))
	ret = append(ret,
		cel.Types(CvssType),
		cel.CustomTypeAdapter(&TypeAdapter{}),
		cel.Variable("cvss", CvssType),
	)
	ret = append(ret, funcs...)
	return ret
}

func (*CvssTool) ProgramOptions() []cel.ProgramOption {
	return nil
}
