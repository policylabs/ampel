// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"crypto/sha1" //nolint:gosec // Needed for compatibility
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"reflect"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
)

type Hasher struct{}

func (h *Hasher) Functions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function(
			"sha256",
			cel.MemberOverload(
				"hasher_sha256_binding",
				[]*cel.Type{HasherType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(s256),
			),
		),
		cel.Function(
			"sha1",
			cel.MemberOverload(
				"hasher_sha21_binding",
				[]*cel.Type{HasherType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(s1),
			),
		),
		cel.Function(
			"sha512",
			cel.MemberOverload(
				"hasher_sha512_binding",
				[]*cel.Type{HasherType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(s512),
			),
		),
	}
}

func (h *Hasher) TypeAdapters() []cel.EnvOption {
	return []cel.EnvOption{
		cel.CustomTypeAdapter(&TypeAdapter{}),
	}
}

func (h *Hasher) Variables() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("hasher", HasherType),
		cel.Variable("hashAlgorithms", types.NewListType(types.StringType)),
	}
}

var s256 = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		h := sha256.New()
		h.Write([]byte(v))
		return types.String(fmt.Sprintf("%x", h.Sum(nil)))
	default:
		return types.NewErr("unsupported type for hash")
	}
}

var s512 = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		h := sha512.New()
		h.Write([]byte(v))
		return types.String(fmt.Sprintf("%x", h.Sum(nil)))
	default:
		return types.NewErr("unsupported type for hash")
	}
}

var s1 = func(_ ref.Val, rhs ref.Val) ref.Val {
	switch v := rhs.Value().(type) {
	case string:
		h := sha1.New() //nolint:gosec // Needed for compatibility
		h.Write([]byte(v))
		return types.String(fmt.Sprintf("%x", h.Sum(nil)))
	default:
		return types.NewErr("unsupported type for hash")
	}
}

var HasherType = cel.ObjectType("hasher", traits.ReceiverType)

func (h *Hasher) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.TypeType:
		return HasherType

	default:
		return types.NewErr("type conversion not allowed for protobom")
	}
}

func (h *Hasher) Type() ref.Type {
	return HasherType
}

func (h *Hasher) Equal(other ref.Val) ref.Val {
	return types.NewErr("objects cannot be compared")
}

func (h *Hasher) Value() any {
	return h
}

func (ch *Hasher) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return nil, errors.New("hashers cannot be converted to native")
}

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	val, ok := value.(Hasher)
	if ok {
		return &val
	} else {
		// let the default adapter handle other cases
		return types.DefaultTypeAdapter.NativeToValue(value)
	}
}

func (h *Hasher) Types() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(HasherType),
	}
}

// CompileOptions and ProgramOptions implement the library

func (h *Hasher) CompileOptions() []cel.EnvOption {
	typesList := h.Types()
	vars := h.Variables()
	funcs := h.Functions()
	adapters := h.TypeAdapters()
	ret := make([]cel.EnvOption, 0, len(typesList)+len(vars)+len(funcs)+len(adapters))
	ret = append(ret, typesList...)
	ret = append(ret, vars...)
	ret = append(ret, funcs...)
	ret = append(ret, adapters...)
	return ret
}

func (p *Hasher) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
