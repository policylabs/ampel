// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package webhook implements an emitter that POSTs the evaluation results as
// JSON to an HTTP(S) endpoint. It is configured with a single value, the
// webhook URL, taken from its initstring (eg "webhook:https://example.com/hook").
//
// Emitting is best-effort: a single POST is attempted with no retries. A
// non-2xx response or a transport error is returned to the publisher, which
// surfaces it without failing the evaluation.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	papi "github.com/carabiner-dev/policy/api/v1"

	"github.com/carabiner-dev/ampel/pkg/publisher"
)

// TypeMoniker is the moniker used to select this emitter in an initstring.
const TypeMoniker = "webhook"

// defaultTimeout bounds a single emit attempt.
const defaultTimeout = 30 * time.Second

// Build constructs a webhook emitter from its init string, which is the full
// webhook URL (everything after the "webhook:" prefix).
func Build(initString string) (publisher.Emitter, error) {
	if initString == "" {
		return nil, errors.New(`webhook emitter requires a URL (eg "webhook:https://example.com/hook")`)
	}
	u, err := url.Parse(initString)
	if err != nil {
		return nil, fmt.Errorf("parsing webhook url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("webhook url must be http or https, got %q", u.Scheme)
	}
	return &Emitter{
		URL:    initString,
		Client: &http.Client{Timeout: defaultTimeout},
	}, nil
}

// Emitter POSTs the evaluation results to URL.
type Emitter struct {
	URL    string
	Client *http.Client
}

// Emit marshals the results to JSON and POSTs them to the configured URL.
func (e *Emitter) Emit(ctx context.Context, results papi.Results, _ ...publisher.EmitOpt) error {
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	data, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.URL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("building webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting to webhook: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort: nothing to do on a close failure
	// Drain the body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck // best-effort drain

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-success status %s", resp.Status)
	}
	return nil
}
