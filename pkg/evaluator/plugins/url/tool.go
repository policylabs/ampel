// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"errors"
	nurl "net/url"
	"reflect"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
)

type UrlTool struct{}

var UrlType = cel.ObjectType("url", traits.ReceiverType)

func (ut *UrlTool) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function(
			"parse",
			cel.MemberOverload(
				"url_parse_binding",
				[]*cel.Type{UrlType, cel.StringType}, cel.MapType(cel.StringType, cel.AnyType),
				cel.BinaryBinding(parse),
			),
		),
	}
}

var parse = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		parsed, err := nurl.Parse(v)
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		m := map[string]string{
			"scheme":   parsed.Scheme,
			"host":     parsed.Hostname(),
			"path":     parsed.Path,
			"fragment": parsed.Fragment,
		}
		reg, err := types.NewRegistry()
		if err != nil {
			return types.NewErrFromString(err.Error())
		}
		return types.NewStringStringMap(reg, m)

	default:
		return types.NewErrFromString("unsupported type for url parse")
	}
}

func (ut *UrlTool) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.TypeType:
		return UrlType

	default:
		return types.NewErr("type conversion not allowed for protobom")
	}
}

func (*UrlTool) Type() ref.Type {
	return UrlType
}

func (*UrlTool) Equal(other ref.Val) ref.Val {
	return types.NewErr("objects cannot be compared")
}

func (ut *UrlTool) Value() any {
	return ut
}

func (*UrlTool) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, errors.New("url cannot be converted to native")
}

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	val, ok := value.(UrlTool)
	if ok {
		return &val
	} else {
		// let the default adapter handle other cases
		return types.DefaultTypeAdapter.NativeToValue(value)
	}
}

// CompileOptions and ProgramOptions implement the cel.Library interface

func (ut *UrlTool) CompileOptions() []cel.EnvOption {
	funcs := ut.Functions()
	ret := make([]cel.EnvOption, 0, 3+len(funcs))
	ret = append(ret,
		cel.Types(UrlType),
		cel.CustomTypeAdapter(&TypeAdapter{}),
		cel.Variable("url", UrlType),
	)
	ret = append(ret, funcs...)
	return ret
}

func (ut *UrlTool) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
