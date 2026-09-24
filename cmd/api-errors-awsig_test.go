// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package cmd

import (
	"context"
	"fmt"
	"testing"

	"github.com/amwolff/awsig"
)

func TestAwsigToAPIErrorCode(t *testing.T) {
	// Mirrors awsig's nested errors, which match both the outer and inner error.
	nested := &testNestedError{outer: awsig.ErrMalformedPOSTRequest, inner: fmt.Errorf("parse: %w", awsig.ErrMissingPOSTFile)}

	for i := 0; i < 20; i++ {
		if code, ok := awsigToAPIErrorCode(nested); !ok || code != ErrMalformedPOSTRequest {
			t.Fatalf("expected ErrMalformedPOSTRequest, got %v, %v", code, ok)
		}
	}

	if code, ok := awsigToAPIErrorCode(fmt.Errorf("x: %w", awsig.ErrMissingPOSTFile)); !ok || code != ErrPOSTFileRequired {
		t.Fatalf("expected ErrPOSTFileRequired, got %v, %v", code, ok)
	}

	// Errors from reading a request body go through ToAPIError.
	if apiErr := ToAPIError(context.Background(), fmt.Errorf("read: %w", awsig.ErrBadDigest)); apiErr.Code != "BadDigest" {
		t.Fatalf("expected BadDigest, got %s", apiErr.Code)
	}
}

type testNestedError struct{ outer, inner error }

func (e *testNestedError) Error() string        { return e.outer.Error() + ": " + e.inner.Error() }
func (e *testNestedError) Unwrap() error        { return e.inner }
func (e *testNestedError) Is(target error) bool { return e.outer == target }
