// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"context"
	"fmt"

	"cel.dev/cel-go/cel"
	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	sapi "github.com/carabiner-dev/signer/api/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	"github.com/carabiner-dev/ampel/pkg/evaluator/evalcontext"
	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/cvss"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/github"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/hasher"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/osv"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/protobom"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/purl"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/semver"
	"github.com/carabiner-dev/ampel/pkg/evaluator/plugins/url"
)

var Class = class.MustParseClass("cel@v1")

// EvaluationError captures error details when executing CEL code
type EvaluationError struct {
	Message   string
	EvalError error
}

func (ee *EvaluationError) Error() string {
	return ee.Message
}

const (
	VarNamePredicate  = "predicate"
	VarNamePredicates = "predicates"
	VarNameContext    = "context"
	VarNameOutputs    = "outputs"
	VarNameSubject    = "subject"
)

// New creates a new CEL evaluator with the default options
func New(funcs ...options.OptFunc) (*Evaluator, error) {
	opts := options.Default
	for _, fn := range funcs {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	return NewWithOptions(&opts)
}

func NewWithOptions(opts *options.EvaluatorOptions) (*Evaluator, error) {
	eval := &Evaluator{
		Plugins: map[string]Plugin{},
		impl:    &defaulCelEvaluator{},
	}
	if err := eval.rebuildEnvironment(opts); err != nil {
		return nil, err
	}
	return eval, nil
}

// Ensure the default plugins implement the cel plugin interface
var (
	_ Plugin = (*hasher.Plugin)(nil)
	_ Plugin = (*osv.Plugin)(nil)
	_ Plugin = (*url.Plugin)(nil)
	_ Plugin = (*github.Plugin)(nil)
	_ Plugin = (*protobom.Plugin)(nil)
	_ Plugin = (*purl.Plugin)(nil)
	_ Plugin = (*semver.Plugin)(nil)
	_ Plugin = (*cvss.Plugin)(nil)
)

// rebuildEnvironment builds the environment with the current settings
func (e *Evaluator) rebuildEnvironment(opts *options.EvaluatorOptions) error {
	if opts.LoadDefaultPlugins {
		if err := e.RegisterPlugin(hasher.New()); err != nil {
			return fmt.Errorf("registering hasher: %w", err)
		}
		if err := e.RegisterPlugin(url.New()); err != nil {
			return fmt.Errorf("registering url: %w", err)
		}
		if err := e.RegisterPlugin(github.New()); err != nil {
			return fmt.Errorf("registering github: %w", err)
		}
		if err := e.RegisterPlugin(protobom.New()); err != nil {
			return fmt.Errorf("registering github: %w", err)
		}
		if err := e.RegisterPlugin(purl.New()); err != nil {
			return fmt.Errorf("registering purl: %w", err)
		}
		if err := e.RegisterPlugin(semver.New()); err != nil {
			return fmt.Errorf("registering semver: %w", err)
		}
		if err := e.RegisterPlugin(cvss.New()); err != nil {
			return fmt.Errorf("registering cvss: %w", err)
		}
		if err := e.RegisterPlugin(osv.New()); err != nil {
			return fmt.Errorf("registering osv: %w", err)
		}
	}

	for _, p := range e.Plugins {
		logrus.Debugf("registered CEL plugin %T version %s", p, p.Identity().Version())
	}

	// Create the env
	env, err := e.impl.CreateEnvironment(opts, e.Plugins)
	if err != nil {
		return fmt.Errorf("creating environment: %w", err)
	}
	e.Environment = env
	return nil
}

// Evaluator implements the evaluator.Evaluator interface to evaluate CEL code
type Evaluator struct {
	Environment *cel.Env
	Plugins     map[string]Plugin
	impl        CelEvaluatorImplementation
}

type Plugin interface {
	api.EvalEnginePlugin

	// Library returns the CEL environment option that registers this plugin's
	// types and functions into the evaluation environment.
	Library() cel.EnvOption

	// VarValues returns the values of the variables handled by the plugin
	VarValues(*papi.Policy, attestation.Subject, []attestation.Predicate) map[string]any
}

// RegisterPlugin registers a plugin expanding the CEL API available at eval time
func (e *Evaluator) RegisterPlugin(plugin api.Plugin) error {
	// Register the plugin in the data collection
	if api.PluginHasCapability(api.CapabilityEvalEnginePlugin, plugin) {
		if p, ok := plugin.(api.EvalEnginePlugin); ok {
			if !p.CanRegisterFor(Class) {
				return nil
			}
		} else {
			return fmt.Errorf("unable to cast plugin to api.EvalEngineDataPlugin")
		}

		dp, ok := plugin.(Plugin)
		if !ok {
			return fmt.Errorf("plugin declares compatibility with %s but does not implement cel.Plugin", Class)
		}
		e.Plugins[dp.Identity().Name()] = dp
	}

	return nil
}

// EvalExpression evaluates a standalone CEL expression against the subject
// carried in the evalcontext and plugin-provided variables, returning its
// resolved value. It is used to resolve dynamic ContextVal expressions.
func (e *Evaluator) EvalExpression(
	ctx context.Context, opts *options.EvaluatorOptions, code string,
) (any, error) {
	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if !ok {
		evalContext = evalcontext.EvaluationContext{}
	}

	vars, err := e.impl.BuildExpressionVariables(opts, e.Plugins, &evalContext)
	if err != nil {
		return nil, fmt.Errorf("building expression variable set: %w", err)
	}

	ast, err := e.impl.CompileCode(e.Environment, code)
	if err != nil {
		return nil, fmt.Errorf("compiling expression: %w", err)
	}

	return e.impl.EvaluateExpression(e.Environment, ast, vars)
}

func (e *Evaluator) ExecChainedSelector(
	ctx context.Context, opts *options.EvaluatorOptions, chained *papi.ChainedPredicate, predicate attestation.Predicate,
) ([]attestation.Subject, error) {
	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if !ok {
		evalContext = evalcontext.EvaluationContext{}
	}

	// Build the variable values for the runtime
	vars, err := e.impl.BuildSelectorVariables(
		opts, e.Plugins, &evalContext, evalContext.Policy, evalContext.Subject, chained, predicate,
	)
	if err != nil {
		return nil, fmt.Errorf("building selector variable set: %w", err)
	}

	ast, err := e.impl.CompileCode(e.Environment, chained.Selector)
	if err != nil {
		return nil, fmt.Errorf("compiling selector program: %w", err)
	}

	subjects, err := e.impl.EvaluateChainedSelector(e.Environment, ast, vars)
	if err != nil {
		return nil, fmt.Errorf("evaluating chained subject: %w", err)
	}
	logrus.Debugf("chained subject from selector: %+v", subjects)
	return subjects, nil
}

// Exec executes each tenet and returns the combined results
func (e *Evaluator) ExecTenet(
	ctx context.Context, opts *options.EvaluatorOptions, tenet *papi.Tenet, predicates []attestation.Predicate,
) (*papi.EvalResult, error) {
	// Build the statement refs to add to the results
	statementRefs := make([]*papi.StatementRef, 0, len(predicates))
	for _, pred := range predicates {
		sref := &papi.StatementRef{
			Type:        string(pred.GetType()),
			Attestation: &intoto.ResourceDescriptor{},
		}

		if v, ok := pred.GetVerification().(*sapi.Verification); ok {
			if v.GetSignature() != nil {
				sref.Identities = v.GetSignature().GetIdentities()
			}
		}

		if pred.GetOrigin() != nil {
			sref.GetAttestation().Name = pred.GetOrigin().GetName()
			sref.GetAttestation().Uri = pred.GetOrigin().GetUri()
			sref.GetAttestation().Digest = pred.GetOrigin().GetDigest()
		}

		statementRefs = append(statementRefs, sref)
	}

	// Compile the tenet code into ASTs
	ast, err := e.impl.CompileCode(e.Environment, tenet.Code)
	if err != nil {
		return nil, fmt.Errorf("compiling program: %w", err)
	}

	outputAsts := map[string]*cel.Ast{}
	for id, output := range tenet.Outputs {
		oast, err := e.impl.CompileCode(e.Environment, output.Code)
		if err != nil {
			return nil, fmt.Errorf("compiling output #%s: %w", id, err)
		}
		outputAsts[id] = oast
	}

	evalContext, ok := ctx.Value(evalcontext.EvaluationContextKey{}).(evalcontext.EvaluationContext)
	if !ok {
		evalContext = evalcontext.EvaluationContext{}
	}

	vars, err := e.impl.BuildVariables(opts, e.Plugins, tenet, &evalContext, predicates)
	if err != nil {
		return nil, fmt.Errorf("building variables for eval environment: %w", err)
	}

	// If the tenet requires predicates, ensure the variables array has them
	status, err := e.impl.EnsurePredicates(tenet, vars)
	if err != nil {
		return nil, fmt.Errorf("ensuring predicates are loaded: %w", err)
	}
	if status != nil {
		return status, nil
	}

	lazy := newLazyExprMap(e.Environment, outputAsts, *vars)
	(*vars)[VarNameOutputs] = lazy

	// Evaluate the ASTs and compile the results into a resultset
	result, err := e.impl.Evaluate(e.Environment, ast, vars)
	if err != nil {
		//nolint:errorlint
		ee, ok := err.(*EvaluationError)
		if ok {
			return &papi.EvalResult{
				Id:         tenet.Id,
				Status:     papi.StatusFAIL,
				Date:       timestamppb.Now(),
				Output:     &structpb.Struct{},
				Statements: statementRefs,
				Error: &papi.Error{
					Message:  "Evaluating policy code: " + ee.Message,
					Guidance: ee.EvalError.Error(),
				},
			}, nil
		}
		return nil, fmt.Errorf("evaluating ASTs: %w", err)
	}
	// TODO(puerco) This should not happen here, Evaluate should init the result
	// with the tenet data
	result.Id = tenet.Id
	result.Statements = statementRefs

	outputMap, err := serializeOutputs(lazy.snapshot())
	if err != nil {
		return nil, fmt.Errorf("serializing outputs: %w", err)
	}

	outStruct, err := structpb.NewStruct(outputMap)
	if err != nil {
		return nil, fmt.Errorf("converting outputs to struct: %w", err)
	}
	result.Output = outStruct

	return result, err
}

func (e *Evaluator) SupportedVersion() string {
	return Class.Version()
}

// RegisteredPlugins returns the plugins registered with this evaluator keyed
// by plugin name.
func (e *Evaluator) RegisteredPlugins() map[string]api.EvalEnginePlugin {
	result := make(map[string]api.EvalEnginePlugin, len(e.Plugins))
	for k, v := range e.Plugins {
		result[k] = v
	}
	return result
}
