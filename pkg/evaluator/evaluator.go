// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"errors"
	"fmt"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/evaluator/cel"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

// Ensure the known evaluators satisfy the interface
var (
	_ Evaluator = (*cel.Evaluator)(nil)
	_ Evaluator = (*versionMismatchEvaluator)(nil)
)

type Factory struct{}

func (f *Factory) Get(opts *options.EvaluatorOptions, c class.Class) (Evaluator, error) {
	var e Evaluator
	var err error
	switch c.Name() {
	case cel.Class.Name():
		e, err = cel.NewWithOptions(opts)
	default:
		return nil, fmt.Errorf("no evaluator defined for class %q", c.Name())
	}
	if err != nil {
		return nil, err
	}

	// When the policy's declared runtime asks for an engine version or plugins
	// this binary cannot satisfy, we route its tenets to a stub evaluator. By
	// default the stub fails them; when the caller opts in via
	// SkipUnsupportedRuntime it soft-fails (skips) them instead.
	mismatchStatus := papi.StatusFAIL
	if opts.SkipUnsupportedRuntime {
		mismatchStatus = papi.StatusSOFTFAIL
	}

	if !class.SupportsVersion(c.Version(), e.SupportedVersion()) {
		return &versionMismatchEvaluator{
			errMsg:    fmt.Sprintf("version %s is not supported by this engine (supports %s@%s)", c.String(), c.Name(), e.SupportedVersion()),
			supported: e.SupportedVersion(),
			status:    mismatchStatus,
		}, nil
	}
	if pp, ok := e.(PluginAware); ok {
		if err := checkPluginRequirements(pp.RegisteredPlugins(), c.Plugins()); err != nil {
			return &versionMismatchEvaluator{ //nolint:nilerr
				errMsg:    err.Error(),
				supported: e.SupportedVersion(),
				status:    mismatchStatus,
			}, nil
		}
	}
	return e, nil
}

// PluginAware is an optional interface for evaluators that register named
// plugins. The factory uses it to check plugin version requirements from the
// policy runtime spec.
type PluginAware interface {
	RegisteredPlugins() map[string]api.EvalEnginePlugin
}

// checkPluginRequirements verifies that every name→version requirement in reqs
// is satisfied by the provided plugins. Returns an error for the first unmet
// requirement.
func checkPluginRequirements(plugins map[string]api.EvalEnginePlugin, reqs map[string]string) error {
	for name, required := range reqs {
		p, ok := plugins[name]
		if !ok {
			return fmt.Errorf("plugin %s@%s is required but not available in this engine", name, required)
		}
		if !class.SupportsVersion(required, p.Identity().Version()) {
			return fmt.Errorf("plugin %s@%s is required but this engine only has %s@%s", name, required, name, p.Identity().Version())
		}
	}
	return nil
}

// Evaluator
type Evaluator interface {
	ExecTenet(context.Context, *options.EvaluatorOptions, *papi.Tenet, []attestation.Predicate) (*papi.EvalResult, error)
	ExecChainedSelector(context.Context, *options.EvaluatorOptions, *papi.ChainedPredicate, attestation.Predicate) ([]attestation.Subject, error)

	// EvalExpression evaluates a standalone expression and returns its value.
	// Used to resolve dynamic ContextVal expressions. The evaluator reads the
	// subject and any other evaluation-time data from the evalcontext.EvaluationContext
	// stored in ctx.
	EvalExpression(context.Context, *options.EvaluatorOptions, string) (any, error)

	// SupportedVersion returns the maximum runtime version this evaluator can
	// satisfy. The factory rejects policy specs that request a higher version.
	SupportedVersion() string
}

// versionMismatchEvaluator is returned by the factory when the policy spec
// requests a runtime or plugin version the engine binary does not support.
// Every tenet routed to it produces a result with status (FAIL by default, or
// SOFTFAIL when the caller opted to skip unsupported runtimes) and a clear
// message; no policy code is executed.
type versionMismatchEvaluator struct {
	errMsg    string
	supported string
	// status is the EvalResult status emitted for every tenet routed here.
	// Empty is treated as FAIL.
	status string
}

func (v *versionMismatchEvaluator) ExecTenet(_ context.Context, _ *options.EvaluatorOptions, tenet *papi.Tenet, _ []attestation.Predicate) (*papi.EvalResult, error) {
	status := v.status
	if status == "" {
		status = papi.StatusFAIL
	}
	return &papi.EvalResult{
		Id:     tenet.GetId(),
		Status: status,
		Date:   timestamppb.Now(),
		Error:  &papi.Error{Message: v.err().Error()},
	}, nil
}

func (v *versionMismatchEvaluator) ExecChainedSelector(_ context.Context, _ *options.EvaluatorOptions, _ *papi.ChainedPredicate, _ attestation.Predicate) ([]attestation.Subject, error) {
	return nil, v.err()
}

func (v *versionMismatchEvaluator) EvalExpression(_ context.Context, _ *options.EvaluatorOptions, _ string) (any, error) {
	return nil, v.err()
}

func (v *versionMismatchEvaluator) SupportedVersion() string {
	return v.supported
}

func (v *versionMismatchEvaluator) err() error {
	return errors.New(v.errMsg)
}
