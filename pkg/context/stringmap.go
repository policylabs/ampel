// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"errors"
	"fmt"
	"strings"
)

// StringMapList returns context data from a list of strings where each
// line has the value preceded by a colon and the value. For example:
//
//	"value1:My Value"
//	"OtherValue:Another value"
//	"Number:3" // This would be a string "3"
//
// All values returned by the provider are strings.
//
// This provider was created to support context strings passed in the CLI
// to the ampel verifier.
type StringMapList []string

// ErrInvalidContextValue is returned when a context value definition is
// not a key:value pair.
var ErrInvalidContextValue = errors.New("invalid context value definition")

// NewStringMapList validates a list of key:value context definitions
// and returns them as a provider. A definition without a colon, with an
// empty key, or with an equals sign or spaces in the key (almost always
// a key=value mixup) never matches a lookup, so it is rejected here
// instead of surfacing later as a missing required context value.
func NewStringMapList(vals []string) (*StringMapList, error) {
	for _, s := range vals {
		key, _, ok := strings.Cut(s, ":")
		switch {
		case !ok:
			return nil, fmt.Errorf("%w %q: expected key:value", ErrInvalidContextValue, s)
		case key == "":
			return nil, fmt.Errorf("%w %q: empty key", ErrInvalidContextValue, s)
		case strings.ContainsAny(key, "= \t"):
			return nil, fmt.Errorf("%w %q: %q is not a plain key (did you write key=value?)", ErrInvalidContextValue, s, key)
		}
	}
	l := StringMapList(vals)
	return &l, nil
}

func (sml *StringMapList) GetContextValue(key string) (any, error) {
	if sml == nil {
		return nil, nil
	}
	pref := key + ":"
	for _, s := range *sml {
		v, ok := strings.CutPrefix(s, pref)
		if ok {
			return v, nil
		}
	}
	return nil, nil
}

func (sml *StringMapList) GetContextMap(keys []string) (map[string]any, error) {
	if sml == nil {
		return nil, nil
	}
	ret := map[string]any{}
	for _, s := range *sml {
		k, v, _ := strings.Cut(s, ":")
		ret[k] = v
	}
	return ret, nil
}
