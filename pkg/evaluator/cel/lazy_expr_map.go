// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"errors"
	"maps"
	"reflect"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
)

// lazyExprMapType is the CEL object type for the lazy expression map value.
var lazyExprMapType = cel.ObjectType("lazyExprMap", traits.IndexerType)

// lazyExprMap is a CEL map value whose entries are backed by pre-compiled CEL
// ASTs evaluated lazily on first access. Entries are accessible via both dot
// notation (map.name) and bracket notation (map["name"]). Results are cached
// for the duration of the evaluation.
// Expressions can reference sibling entries and they resolve recursively,
// circular references are detected and returned as errors.
type lazyExprMap struct {
	asts       map[string]*cel.Ast
	env        *cel.Env
	vars       map[string]any
	cache      map[string]ref.Val
	inProgress map[string]bool
}

func newLazyExprMap(env *cel.Env, asts map[string]*cel.Ast, vars map[string]any) *lazyExprMap {
	return &lazyExprMap{
		asts:       asts,
		env:        env,
		vars:       vars,
		cache:      make(map[string]ref.Val, len(asts)),
		inProgress: make(map[string]bool, len(asts)),
	}
}

func (lo *lazyExprMap) Type() ref.Type {
	return lazyExprMapType
}

func (lo *lazyExprMap) Value() any {
	return lo.cache
}

func (lo *lazyExprMap) Equal(_ ref.Val) ref.Val {
	return types.NewErr("lazyExprMap cannot be compared")
}

func (lo *lazyExprMap) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("lazyExprMap cannot be converted to native")
}

func (lo *lazyExprMap) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal == types.TypeType {
		return lazyExprMapType
	}
	return types.NewErr("type conversion not supported for lazyExprMap")
}

// Get implements traits.Indexer. On the first access of a named entry it
// evaluates the pre-compiled AST against the full variable set and caches
// the result. A cycle, where evaluating entry A triggers evaluation of entry
// B which in turn needs A, is detected and returned as an error.
func (lo *lazyExprMap) Get(index ref.Val) ref.Val {
	name, ok := index.Value().(string)
	if !ok {
		return types.NewErr("lazyExprMap key must be a string")
	}
	if v, ok := lo.cache[name]; ok {
		return v
	}
	if lo.inProgress[name] {
		return types.NewErr("cycle detected evaluating: %s", name)
	}
	ast, ok := lo.asts[name]
	if !ok {
		return types.NewErr("unknown entry: %s", name)
	}
	lo.inProgress[name] = true
	defer func() {
		lo.inProgress[name] = false
	}()
	program, err := lo.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return types.NewErr("building program for %s: %v", name, err)
	}
	result, _, err := program.Eval(lo.vars)
	if err != nil {
		return types.NewErr("evaluating %s: %v", name, err)
	}
	lo.cache[name] = result
	return result
}

// snapshot returns a copy of the entries that were actually evaluated.
// Entries never referenced during the evaluation are absent.
func (lo *lazyExprMap) snapshot() map[string]ref.Val {
	snap := make(map[string]ref.Val, len(lo.cache))
	maps.Copy(snap, lo.cache)
	return snap
}

var (
	_ ref.Val        = (*lazyExprMap)(nil)
	_ traits.Indexer = (*lazyExprMap)(nil)
)
