// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package semver

import (
	"errors"
	"reflect"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	msemver "github.com/Masterminds/semver/v3"
)

// SemverTool is the host object for the `semver.*` methods in CEL.
type SemverTool struct{}

// SemverType is the CEL object type registered for the `semver`
// global. Like the other plugin tools, it is an opaque handle the
// CEL compiler uses to dispatch method calls.
var SemverType = cel.ObjectType("semver", traits.ReceiverType)

// Functions registers the member overloads exposed on the semver
// object. Every accessor accepts a string and either returns a
// numeric/string component or a bool — the failure mode for an
// unparseable input is a CEL error that surfaces at evaluation
// time.
func (st *SemverTool) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		// Accessors returning ints.
		memberIntFn("major", majorFn),
		memberIntFn("minor", minorFn),
		memberIntFn("patch", patchFn),

		// Accessors returning strings.
		memberStringFn("prerelease", prereleaseFn),
		memberStringFn("build", buildFn),

		// Validation predicates.
		memberBoolFn("isValid", isValidFn),
		memberBoolFn("isStable", isStableFn),

		// Binary comparisons (two version strings).
		memberBinaryBoolFn("isNewer", isNewerFn),
		memberBinaryBoolFn("isOlder", isOlderFn),
		memberBinaryBoolFn("equal", equalFn),
		cel.Function(
			"compare",
			cel.MemberOverload(
				"semver_compare_binding",
				[]*cel.Type{SemverType, cel.StringType, cel.StringType}, cel.IntType,
				cel.FunctionBinding(compareFn),
			),
		),

		// Constraint matching (npm/composer-style expressions).
		cel.Function(
			"satisfies",
			cel.MemberOverload(
				"semver_satisfies_binding",
				[]*cel.Type{SemverType, cel.StringType, cel.StringType}, cel.BoolType,
				cel.FunctionBinding(satisfiesFn),
			),
		),

		// Full parse — returns a map mirroring the other plugins'
		// parse() convention.
		cel.Function(
			"parse",
			cel.MemberOverload(
				"semver_parse_binding",
				[]*cel.Type{SemverType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(parseFn),
			),
		),
	}
}

// memberIntFn is shorthand for the "member(semver, string) → int"
// shape used by major/minor/patch.
func memberIntFn(name string, fn func(string) (int64, error)) cel.EnvOption {
	return cel.Function(
		name,
		cel.MemberOverload(
			"semver_"+name+"_binding",
			[]*cel.Type{SemverType, cel.StringType}, cel.IntType,
			cel.BinaryBinding(stringToIntAdapter(fn)),
		),
	)
}

// memberStringFn is the "(semver, string) → string" helper.
func memberStringFn(name string, fn func(string) (string, error)) cel.EnvOption {
	return cel.Function(
		name,
		cel.MemberOverload(
			"semver_"+name+"_binding",
			[]*cel.Type{SemverType, cel.StringType}, cel.StringType,
			cel.BinaryBinding(stringToStringAdapter(fn)),
		),
	)
}

// memberBoolFn is the "(semver, string) → bool" helper.
func memberBoolFn(name string, fn func(string) (bool, error)) cel.EnvOption {
	return cel.Function(
		name,
		cel.MemberOverload(
			"semver_"+name+"_binding",
			[]*cel.Type{SemverType, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(stringToBoolAdapter(fn)),
		),
	)
}

// memberBinaryBoolFn is the "(semver, string, string) → bool"
// helper used by the pairwise comparison predicates.
func memberBinaryBoolFn(name string, fn func(a, b string) (bool, error)) cel.EnvOption {
	return cel.Function(
		name,
		cel.MemberOverload(
			"semver_"+name+"_binding",
			[]*cel.Type{SemverType, cel.StringType, cel.StringType}, cel.BoolType,
			cel.FunctionBinding(twoStringsToBoolAdapter(fn)),
		),
	)
}

// ---- CEL adapter glue ---------------------------------------------------

func stringToIntAdapter(fn func(string) (int64, error)) func(lhs, rhs ref.Val) ref.Val {
	return func(_, rhs ref.Val) ref.Val {
		s, err := asString(rhs, "int accessor")
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		v, err := fn(s)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.Int(v)
	}
}

func stringToStringAdapter(fn func(string) (string, error)) func(lhs, rhs ref.Val) ref.Val {
	return func(_, rhs ref.Val) ref.Val {
		s, err := asString(rhs, "string accessor")
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		v, err := fn(s)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.String(v)
	}
}

func stringToBoolAdapter(fn func(string) (bool, error)) func(lhs, rhs ref.Val) ref.Val {
	return func(_, rhs ref.Val) ref.Val {
		s, err := asString(rhs, "bool accessor")
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		v, err := fn(s)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.Bool(v)
	}
}

func twoStringsToBoolAdapter(fn func(a, b string) (bool, error)) func(args ...ref.Val) ref.Val {
	return func(args ...ref.Val) ref.Val {
		if len(args) != 3 {
			return types.NewErrFromString("semver comparison needs two string args")
		}
		a, err := asString(args[1], "first version")
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		b, err := asString(args[2], "second version")
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		v, err := fn(a, b)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.Bool(v)
	}
}

// compareFn is not a predicate — it returns Int — so it has its
// own adapter.
func compareFn(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NewErrFromString("semver.compare needs two string args")
	}
	a, err := asString(args[1], "first version")
	if err != nil {
		return types.NewErrFromString(err.Error())
	}
	b, err := asString(args[2], "second version")
	if err != nil {
		return types.NewErrFromString(err.Error())
	}
	av, err := msemver.NewVersion(a)
	if err != nil {
		return types.NewErrFromString("invalid semver: " + a)
	}
	bv, err := msemver.NewVersion(b)
	if err != nil {
		return types.NewErrFromString("invalid semver: " + b)
	}
	return types.Int(av.Compare(bv))
}

func satisfiesFn(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NewErrFromString("semver.satisfies needs a version and a constraint")
	}
	v, err := asString(args[1], "version")
	if err != nil {
		return types.NewErrFromString(err.Error())
	}
	constraint, err := asString(args[2], "constraint")
	if err != nil {
		return types.NewErrFromString(err.Error())
	}
	parsed, err := msemver.NewVersion(v)
	if err != nil {
		return types.NewErrFromString("invalid semver: " + v)
	}
	c, err := msemver.NewConstraint(constraint)
	if err != nil {
		return types.NewErrFromString("invalid constraint: " + constraint)
	}
	return types.Bool(c.Check(parsed))
}

func parseFn(_, rhs ref.Val) ref.Val {
	s, err := asString(rhs, "version")
	if err != nil {
		return types.NewErrFromString(err.Error())
	}
	parsed, err := msemver.NewVersion(s)
	if err != nil {
		return types.NewErrFromString("invalid semver: " + s)
	}
	reg, err := types.NewRegistry()
	if err != nil {
		return types.NewErrFromString(err.Error())
	}
	return types.NewDynamicMap(reg, map[string]any{
		//nolint:gosec // semver components are always small (major/minor/patch), overflow is not a real risk
		"major": int64(parsed.Major()),
		//nolint:gosec // semver components are always small (major/minor/patch), overflow is not a real risk
		"minor": int64(parsed.Minor()),
		//nolint:gosec // semver components are always small (major/minor/patch), overflow is not a real risk
		"patch":      int64(parsed.Patch()),
		"prerelease": parsed.Prerelease(),
		"build":      parsed.Metadata(),
		"original":   parsed.Original(),
	})
}

// ---- Business logic -----------------------------------------------------

func majorFn(s string) (int64, error) {
	v, err := msemver.NewVersion(s)
	if err != nil {
		return 0, err
	}
	return int64(v.Major()), nil //nolint:gosec // semver major never overflows int64
}

func minorFn(s string) (int64, error) {
	v, err := msemver.NewVersion(s)
	if err != nil {
		return 0, err
	}
	return int64(v.Minor()), nil //nolint:gosec // semver minor never overflows int64
}

func patchFn(s string) (int64, error) {
	v, err := msemver.NewVersion(s)
	if err != nil {
		return 0, err
	}
	return int64(v.Patch()), nil //nolint:gosec // semver patch never overflows int64
}

func prereleaseFn(s string) (string, error) {
	v, err := msemver.NewVersion(s)
	if err != nil {
		return "", err
	}
	return v.Prerelease(), nil
}

func buildFn(s string) (string, error) {
	v, err := msemver.NewVersion(s)
	if err != nil {
		return "", err
	}
	return v.Metadata(), nil
}

func isValidFn(s string) (bool, error) {
	_, err := msemver.NewVersion(s)
	return err == nil, nil
}

func isStableFn(s string) (bool, error) {
	v, err := msemver.NewVersion(s)
	if err != nil {
		return false, err
	}
	return v.Major() >= 1 && v.Prerelease() == "", nil
}

func isNewerFn(a, b string) (bool, error) {
	av, err := msemver.NewVersion(a)
	if err != nil {
		return false, err
	}
	bv, err := msemver.NewVersion(b)
	if err != nil {
		return false, err
	}
	return av.GreaterThan(bv), nil
}

func isOlderFn(a, b string) (bool, error) {
	av, err := msemver.NewVersion(a)
	if err != nil {
		return false, err
	}
	bv, err := msemver.NewVersion(b)
	if err != nil {
		return false, err
	}
	return av.LessThan(bv), nil
}

func equalFn(a, b string) (bool, error) {
	av, err := msemver.NewVersion(a)
	if err != nil {
		return false, err
	}
	bv, err := msemver.NewVersion(b)
	if err != nil {
		return false, err
	}
	return av.Equal(bv), nil
}

// asString unwraps a CEL ref.Val into a Go string or a descriptive
// error identifying which argument slot was bad.
func asString(v ref.Val, slot string) (string, error) {
	switch x := v.Value().(type) {
	case string:
		return x, nil
	default:
		return "", errors.New("expected string for " + slot)
	}
}

// ---- cel.Library / ref.Val boilerplate ----------------------------------

func (st *SemverTool) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal == types.TypeType {
		return SemverType
	}
	return types.NewErr("type conversion not allowed for semver")
}

func (*SemverTool) Type() ref.Type { return SemverType }

func (*SemverTool) Equal(_ ref.Val) ref.Val {
	return types.NewErr("objects cannot be compared")
}

func (st *SemverTool) Value() any { return st }

func (*SemverTool) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("semver cannot be converted to native")
}

// TypeAdapter registers SemverTool with CEL's runtime type system.
type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	if val, ok := value.(SemverTool); ok {
		return &val
	}
	return types.DefaultTypeAdapter.NativeToValue(value)
}

func (st *SemverTool) CompileOptions() []cel.EnvOption {
	funcs := st.Functions()
	ret := make([]cel.EnvOption, 0, 3+len(funcs))
	ret = append(ret,
		cel.Types(SemverType),
		cel.CustomTypeAdapter(&TypeAdapter{}),
		cel.Variable("semver", SemverType),
	)
	ret = append(ret, funcs...)
	return ret
}

func (*SemverTool) ProgramOptions() []cel.ProgramOption { return nil }
