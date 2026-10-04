// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"errors"
	"os"
	"strings"
)

func NewEnvContextReader() *EnvContextReader {
	return &EnvContextReader{
		VarPrefix: "AMPEL",
	}
}

// EnvContextReader is a context provider that reads context data from
// environment variables. In order to provide some isolation, values are
// (optionally but recommended) prefixed with a string (defaults to "AMPEL_").
//
// The envvar context reader will look for the context values by reading an
// environment variable formed by the prefix, an underscore and uppercasing
// it all. For example, if the context expects a value called "test", the
// provider will look for a an environment var called AMPEL_TEST.
type EnvContextReader struct {
	VarPrefix string
}

func (ecr *EnvContextReader) GetContextValue(key string) (any, error) {
	if key == "" {
		return nil, errors.New("environment variable key empty")
	}
	prefix := ""
	if ecr.VarPrefix != "" {
		prefix = ecr.VarPrefix + "_"
	}
	// Look up the environment var by forming the var name:
	// prefix and uppercase
	v, ok := os.LookupEnv(strings.ToUpper(prefix + key))
	if ok {
		return v, nil
	}
	return nil, nil
}

func (ecr *EnvContextReader) GetContextMap(keys []string) (map[string]any, error) {
	ret := map[string]any{}
	for _, k := range keys {
		v, err := ecr.GetContextValue(k)
		if err != nil {
			return nil, err
		}
		if v != nil {
			ret[k] = v
		}
	}
	return ret, nil
}
