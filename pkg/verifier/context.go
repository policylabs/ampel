// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	papi "github.com/policylabs/policy/api/v1"
)

const (
	valueTrue  = "true"
	valueFalse = "false"
)

// ensureContextType makes sure the loaded context values are match the types
// defined in the context definition. For now we ensure the types of simple
// types: string, bool, int and convert between them as much as possible.
func ensureContextType(value any, contextDef *papi.ContextVal) (any, error) {
	switch contextDef.Type {
	case papi.ContextTypeString:
		return convertToString(value), nil
	case papi.ContextTypeInt:
		return convertToInt64(value)
	case papi.ContextTypeBool:
		return convertToBool(value)
	default:
		return value, nil
	}
}

// convertToString converts any value to a string representation. If its an
// unhandled type wel use sptintf("%v") to convert it.
func convertToString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	case bool:
		if v {
			return valueTrue
		}
		return valueFalse
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%v", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// convertToBool converts any of the simple types to their intended type
func convertToBool(value any) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		if strings.EqualFold(v, valueTrue) {
			return true, nil
		} else if strings.EqualFold(v, valueFalse) {
			return false, nil
		}
		// Try to parse as number
		if num, err := strconv.ParseFloat(v, 64); err == nil {
			return numToBool(num), nil
		}
		return false, fmt.Errorf("convert string %q to bool", v)
	case int:
		return numToBool(float64(v)), nil
	case int8:
		return numToBool(float64(v)), nil
	case int16:
		return numToBool(float64(v)), nil
	case int32:
		return numToBool(float64(v)), nil
	case int64:
		return numToBool(float64(v)), nil
	case uint:
		return numToBool(float64(v)), nil
	case uint8:
		return numToBool(float64(v)), nil
	case uint16:
		return numToBool(float64(v)), nil
	case uint32:
		return numToBool(float64(v)), nil
	case uint64:
		return numToBool(float64(v)), nil
	case float32:
		return numToBool(float64(v)), nil
	case float64:
		return numToBool(v), nil
	default:
		return false, fmt.Errorf("cannot convert type %T to bool", v)
	}
}

// numToBool converts anything over zero to true.
func numToBool(n float64) bool {
	return n > 0
}

// convertToInt64 converts the simple types to int64
func convertToInt64(value any) (int64, error) {
	switch v := value.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case uint:
		// uint is platform sized, so widen before comparing: on 32-bit builds
		// the untyped MaxInt64 constant does not fit in a uint.
		if uint64(v) > math.MaxInt64 {
			return 0, fmt.Errorf("uint value %d overflows int64", v)
		}
		return int64(v), nil
	case uint8:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint64:
		if v > math.MaxInt64 {
			return 0, fmt.Errorf("uint64 value %d overflows int64", v)
		}
		return int64(v), nil
	case float32:
		return int64(math.Round(float64(v))), nil
	case float64:
		return int64(math.Round(v)), nil
	case bool:
		if v {
			return 1, nil
		}
		return 0, nil
	case string:
		// Try to parse as float first (to handle decimals)
		if f, err := strconv.ParseFloat(v, 64); strings.Contains(v, ".") && err == nil {
			return int64(math.Round(f)), nil
		}
		// If its not a float, then as int64
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i, nil
		}
		return 0, fmt.Errorf("convert string %q to int64", v)
	default:
		return 0, fmt.Errorf("cannot convert type %T to int64", v)
	}
}
