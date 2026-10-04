// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"math"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/stretchr/testify/require"
)

func TestConvertToString(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		// String preservation
		{"string preserved", "hello", "hello"},
		{"empty string", "", ""},

		// Bool to string
		{"bool true", true, "true"},
		{"bool false", false, "false"},

		// Integers to string
		{"int", 42, "42"},
		{"int8", int8(-128), "-128"},
		{"int16", int16(1000), "1000"},
		{"int32", int32(-50000), "-50000"},
		{"int64", int64(9223372036854775807), "9223372036854775807"},
		{"negative int", -42, "-42"},

		// Unsigned integers to string
		{"uint", uint(42), "42"},
		{"uint8", uint8(255), "255"},
		{"uint16", uint16(65535), "65535"},
		{"uint32", uint32(4294967295), "4294967295"},
		{"uint64", uint64(18446744073709551615), "18446744073709551615"},

		// Floats to string
		{"float32", float32(3.14), "3.14"},
		{"float64", float64(2.718281828), "2.718281828"},
		{"negative float", float64(-1.5), "-1.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ensureContextType(tt.input, &papi.ContextVal{Type: "string"})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConvertToBool(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     any
		expected  bool
		shouldErr bool
	}{
		// Bool preservation
		{"bool true preserved", true, true, false},
		{"bool false preserved", false, false, false},

		// String to bool
		{"string true", "true", true, false},
		{"string false", "false", false, false},
		{"string number 1", "1", true, false},
		{"string number 0", "0", false, false},
		{"invalid string", "maybe", false, true},

		// Numbers to bool
		{"int_1", 1, true, false},
		{"int_0", 0, false, false},
		{"int_other", 42, true, false},
		{"int_negative", -1, false, false},
		{"int8_1", int8(1), true, false},
		{"int16_0", int16(0), false, false},
		{"int32_1", int32(1), true, false},
		{"int64_0", int64(0), false, false},
		{"uint_1", uint(1), true, false},
		{"uint_0", uint(0), false, false},
		{"uint8_1", uint8(1), true, false},
		{"uint16_0", uint16(0), false, false},
		{"uint32_1", uint32(1), true, false},
		{"uint64_0", uint64(0), false, false},
		{"float32_1.0", float32(1.0), true, false},
		{"float32_0.0", float32(0.0), false, false},
		{"float64_1.0", float64(1.0), true, false},
		{"float64_0.0", float64(0.0), false, false},
		{"float64_0.9", float64(0.9), true, false},
		{"float64_1.1", float64(1.1), true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := ensureContextType(tt.input, &papi.ContextVal{Type: "bool"})
			if tt.shouldErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertToInt64(t *testing.T) {
	tests := []struct {
		name      string
		input     any
		expected  int64
		shouldErr bool
	}{
		// Integer preservation
		{"int64 preserved", int64(42), 42, false},
		{"int", 100, 100, false},
		{"int8", int8(-128), -128, false},
		{"int16", int16(1000), 1000, false},
		{"int32", int32(-50000), -50000, false},
		{"negative int64", int64(-9223372036854775808), -9223372036854775808, false},

		// Unsigned integers
		{"uint", uint(42), 42, false},
		{"uint8", uint8(255), 255, false},
		{"uint16", uint16(65535), 65535, false},
		{"uint32", uint32(4294967295), 4294967295, false},
		{"uint64 valid", uint64(100), 100, false},
		{"uint64 max valid", uint64(math.MaxInt64), math.MaxInt64, false},
		{"uint64 overflow", uint64(math.MaxUint64), 0, true},
		{"uint overflow", uint(math.MaxUint64), 0, true},

		// Float rounding
		{"float32_round_down", float32(3.4), 3, false},
		{"float32_round_up", float32(3.5), 4, false},
		{"float64_round_down", float64(2.4), 2, false},
		{"float64_round_up", float64(2.5), 3, false},
		{"float64_negative_round", float64(-2.5), -3, false},
		{"float64_exact_half_up", float64(0.5), 1, false},
		{"float64_exact_half_down", float64(-0.5), -1, false},

		// Bool to int64
		{"bool true", true, 1, false},
		{"bool false", false, 0, false},

		// String to int64
		{"string int", "42", 42, false},
		{"string negative", "-100", -100, false},
		{"string float", "3.7", 4, false},
		{"string float negative", "-3.7", -4, false},
		{"string invalid", "not a number", 0, true},
		{"string empty", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ensureContextType(tt.input, &papi.ContextVal{Type: "int"})
			if tt.shouldErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test edge cases of the different type conversions
func TestEdgeCases(t *testing.T) {
	t.Run("zero_values", func(t *testing.T) {
		// Zero int to string
		s, _ := ensureContextType(0, &papi.ContextVal{Type: "string"}) //nolint:errcheck // Not checking errors
		if s != "0" {
			t.Errorf("zero int to string: got %v, want '0'", s)
		}

		// Zero float to string
		s2, _ := ensureContextType(0.0, &papi.ContextVal{Type: "string"}) //nolint:errcheck // Not checking errors
		if s2 != "0" {
			t.Errorf("zero float to string: got %v, want '0'", s2)
		}

		// Zero string to int64
		i, _ := ensureContextType("0", &papi.ContextVal{Type: "int"}) //nolint:errcheck // Not checking errors
		if i.(int64) != 0 {                                           //nolint:errcheck,forcetypeassert
			t.Errorf("zero string to int64 huh: got %v, want 0", i)
		}
	})

	t.Run("max_values", func(t *testing.T) {
		// MaxInt64 conversions
		i := int64(math.MaxInt64) - 1
		s, _ := ensureContextType(i, &papi.ContextVal{Type: "string"}) //nolint:errcheck // Not checking errors
		if s != "9223372036854775806" {
			t.Errorf("MaxInt64 to string failed: %v", s)
		}

		// String back to int64
		i2, _ := ensureContextType(s, &papi.ContextVal{Type: "int"}) //nolint:errcheck // Not checking errors
		if i2 != i {
			t.Errorf("MaxInt64 round trip failed: got %v, want %v", i2, i)
		}
	})

	t.Run("float_precision", func(t *testing.T) {
		// Test rounding at .5 boundary
		tests := []struct {
			input    float64
			expected int64
		}{
			{1.5, 2},
			{2.5, 3},
			{-1.5, -2},
			{-2.5, -3},
		}

		for _, tt := range tests {
			result, _ := ensureContextType(tt.input, &papi.ContextVal{Type: "int"}) //nolint:errcheck // Not checking errors
			if result != tt.expected {
				t.Errorf("rounding %v: got %v, want %v", tt.input, result, tt.expected)
			}
		}
	})
}

// Benchmark tests
func BenchmarkConvertToString(b *testing.B) {
	for b.Loop() {
		ensureContextType(42, &papi.ContextVal{Type: "string"}) //nolint:errcheck,gosec // Not checking errors
	}
}

func BenchmarkConvertToBool(b *testing.B) {
	for b.Loop() {
		ensureContextType("true", &papi.ContextVal{Type: "bool"}) //nolint:errcheck,gosec // Not checking errors
	}
}

func BenchmarkConvertToInt64(b *testing.B) {
	for b.Loop() {
		ensureContextType(3.14, &papi.ContextVal{Type: "int"}) //nolint:errcheck,gosec // Not checking errors
	}
}
