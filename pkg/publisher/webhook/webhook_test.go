// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/stretchr/testify/require"
)

func TestBuild(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		spec    string
		mustErr bool
		wantURL string
	}{
		{name: "bare-uri", spec: "https://example.com/hook", wantURL: "https://example.com/hook"},
		{name: "uri-with-query", spec: "https://host/hook?token=abc", wantURL: "https://host/hook?token=abc"},
		{name: "http-ok", spec: "http://example.com/hook", wantURL: "http://example.com/hook"},
		{name: "missing-uri", spec: "", mustErr: true},
		{name: "bad-scheme", spec: "ftp://example.com/hook", mustErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := Build(tc.spec)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			emitter, ok := p.(*Emitter)
			require.True(t, ok)
			require.Equal(t, tc.wantURL, emitter.URL)
		})
	}
}

func TestPublish(t *testing.T) {
	t.Parallel()
	var gotBody []byte
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body) //nolint:errcheck // test handler
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := &Emitter{URL: srv.URL}
	rs := &papi.ResultSet{
		PolicySet: &papi.PolicyRef{Id: "test-set"},
		Status:    papi.StatusPASS,
	}
	require.NoError(t, e.Emit(context.Background(), rs))
	require.Equal(t, "application/json", gotContentType)
	require.Contains(t, string(gotBody), "test-set")
}

func TestPublishNonSuccess(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := &Emitter{URL: srv.URL}
	require.Error(t, e.Emit(context.Background(), &papi.ResultSet{}))
}
