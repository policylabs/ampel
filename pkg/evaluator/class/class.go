// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package class

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Identity is a validated versioned name identifier for a plugin or transformer.
// Format: "name@vN"
type Identity struct {
	name    string
	version string
}

func (i *Identity) Name() string {
	return i.name
}

func (i *Identity) Version() string {
	return i.version
}

func (i *Identity) String() string {
	if i.version == "" {
		return i.name
	}
	return i.name + "@" + i.version
}

// ParseIdentity parses and validates a versioned name string.
func ParseIdentity(s string) (*Identity, error) {
	if s == "" {
		return nil, fmt.Errorf("identity string must not be empty")
	}
	name, version, _ := strings.Cut(s, "@")
	if name == "" {
		return nil, fmt.Errorf("identity %q: name must not be empty", s)
	}
	if version != "" {
		if err := validateVersion(version, s); err != nil {
			return nil, err
		}
	}
	return &Identity{name: name, version: version}, nil
}

// MustParseIdentity parses a versioned name string and panics on error.
func MustParseIdentity(s string) *Identity {
	i, err := ParseIdentity(s)
	if err != nil {
		panic(fmt.Sprintf("MustParseIdentity(%q): %v", s, err))
	}
	return i
}

// Class is a full policy runtime specification: the base evaluator name@version
// plus optional plugin and transformer version requirements.
// Format: "name@version[?plugin:name=version[&transformer:name=version...]]"
// Example: "cel@v1?plugin:semver=v1&transformer:protobom=v1"
type Class string

// BaseClass returns the base "name@version" part of the class, stripping any
// plugin/transformer requirements.
func (c *Class) BaseClass() Class {
	base, _, _ := strings.Cut(string(*c), "?")
	return Class(base)
}

// Identity returns the base name and version as a parsed Identity.
// Panics if the class string is malformed; use ParseClass before calling this.
func (c *Class) Identity() *Identity {
	base, _, _ := strings.Cut(string(*c), "?")
	return MustParseIdentity(base)
}

// Version returns the evaluator version from the class.
func (c *Class) Version() string {
	base, _, _ := strings.Cut(string(*c), "?")
	_, version, _ := strings.Cut(base, "@")
	return version
}

// Name returns the evaluator name from the class.
func (c *Class) Name() string {
	base, _, _ := strings.Cut(string(*c), "?")
	name, _, _ := strings.Cut(base, "@")
	return name
}

// Plugins returns the plugin name→version requirements declared in the class.
// Returns nil if no plugin requirements are set.
func (c *Class) Plugins() map[string]string {
	return c.requirementsByKind("plugin")
}

// Transformers returns the transformer name→version requirements declared in the class.
// Returns nil if no transformer requirements are set.
func (c *Class) Transformers() map[string]string {
	return c.requirementsByKind("transformer")
}

// String returns the class string.
func (c *Class) String() string {
	return string(*c)
}

// requirementsByKind parses the query string and returns requirements whose
// key prefix matches kind (e.g. "plugin" or "transformer").
func (c *Class) requirementsByKind(kind string) map[string]string {
	_, qs, ok := strings.Cut(string(*c), "?")
	if !ok {
		return nil
	}
	vals, err := url.ParseQuery(qs)
	if err != nil {
		return nil
	}
	prefix := kind + ":"
	var result map[string]string
	for key, versions := range vals {
		name, found := strings.CutPrefix(key, prefix)
		if !found {
			continue
		}
		version := ""
		if len(versions) > 0 {
			version = versions[0]
		}
		if result == nil {
			result = map[string]string{}
		}
		result[name] = version
	}
	return result
}

// ParseClass parses and validates a class string. The evaluator name must be
// non-empty, and versions must be in vN format. Each query param key must have a
// recognised prefix ("plugin:" or "transformer:"), a non-empty name, and
// a valid vN version value.
func ParseClass(s string) (Class, error) {
	if s == "" {
		return "", fmt.Errorf("class string must not be empty")
	}
	base, qs, hasRequirements := strings.Cut(s, "?")

	if err := validateBase(base, s); err != nil {
		return "", err
	}

	if hasRequirements {
		vals, err := url.ParseQuery(qs)
		if err != nil {
			return "", fmt.Errorf("class %q: invalid query string: %w", s, err)
		}
		for key, versions := range vals {
			kind, name, ok := strings.Cut(key, ":")
			if !ok {
				return "", fmt.Errorf("class %q: requirement key %q must have a kind prefix (plugin: or transformer:)", s, key)
			}
			if kind != "plugin" && kind != "transformer" {
				return "", fmt.Errorf("class %q: unknown requirement kind %q (must be plugin or transformer)", s, kind)
			}
			if name == "" {
				return "", fmt.Errorf("class %q: %s requirement has an empty name", s, kind)
			}
			version := ""
			if len(versions) > 0 {
				version = versions[0]
			}
			if version == "" {
				return "", fmt.Errorf("class %q: %s %q has no version", s, kind, name)
			}
			if err := validateVersion(version, s); err != nil {
				return "", err
			}
		}
	}

	return Class(s), nil
}

// MustParseClass parses a class string and panics on error.
// Intended for package-level var declarations and test helpers.
func MustParseClass(s string) Class {
	c, err := ParseClass(s)
	if err != nil {
		panic(fmt.Sprintf("MustParseClass(%q): %v", s, err))
	}
	return c
}

// SupportsVersion reports whether the requested version is satisfied by the
// supported version. An empty requested version is treated as compatible.
// Versions are numeric suffixes: "v0", "v1", etc.
func SupportsVersion(requested, supported string) bool {
	if requested == "" {
		return true
	}
	req, err := strconv.Atoi(strings.TrimPrefix(requested, "v"))
	if err != nil {
		return false
	}
	sup, err := strconv.Atoi(strings.TrimPrefix(supported, "v"))
	if err != nil {
		return false
	}
	return req <= sup
}

// validateBase checks that a name@version string has a non-empty name and,
// if a version is present, that it is in vN format.
func validateBase(s, context string) error {
	name, version, _ := strings.Cut(s, "@")
	if name == "" {
		return fmt.Errorf("class %q: %q has an empty name", context, s)
	}
	if version == "" {
		return nil
	}
	return validateVersion(version, context)
}

func validateVersion(version, context string) error {
	if !strings.HasPrefix(version, "v") {
		return fmt.Errorf("class %q: version %q must start with 'v'", context, version)
	}
	if _, err := strconv.Atoi(strings.TrimPrefix(version, "v")); err != nil {
		return fmt.Errorf("class %q: version %q must be in vN format (e.g. v0, v1)", context, version)
	}
	return nil
}
