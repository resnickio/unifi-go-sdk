package unifi

import (
	"errors"
	"testing"
)

func TestAPIErrorError(t *testing.T) {
	err := &APIError{
		StatusCode: 404,
		Message:    "host not found",
		Err:        ErrNotFound,
	}

	expected := "unifi api error (status 404): host not found"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestAPIErrorUnwrap(t *testing.T) {
	err := &APIError{
		StatusCode: 404,
		Message:    "host not found",
		Err:        ErrNotFound,
	}

	if !errors.Is(err, ErrNotFound) {
		t.Error("expected errors.Is(err, ErrNotFound) to be true")
	}
}

func TestAPIErrorUnwrapNil(t *testing.T) {
	err := &APIError{
		StatusCode: 418,
		Message:    "teapot",
		Err:        nil,
	}

	if errors.Is(err, ErrNotFound) {
		t.Error("expected errors.Is(err, ErrNotFound) to be false")
	}
	if errors.Is(err, ErrBadRequest) {
		t.Error("expected errors.Is(err, ErrBadRequest) to be false")
	}
}

func TestSentinelErrors(t *testing.T) {
	sentinels := []error{
		ErrBadRequest,
		ErrUnauthorized,
		ErrForbidden,
		ErrNotFound,
		ErrConflict,
		ErrRateLimited,
		ErrServerError,
		ErrBadGateway,
		ErrServiceUnavail,
		ErrGatewayTimeout,
	}

	for _, sentinel := range sentinels {
		if sentinel == nil {
			t.Error("sentinel error should not be nil")
		}
		if sentinel.Error() == "" {
			t.Error("sentinel error message should not be empty")
		}
	}
}

func TestErrorsAs(t *testing.T) {
	err := &APIError{
		StatusCode: 401,
		Message:    "invalid api key",
		Err:        ErrUnauthorized,
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Error("expected errors.As to succeed")
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("expected status code 401, got %d", apiErr.StatusCode)
	}
}

func TestSentinelForStatusCode(t *testing.T) {
	tests := []struct {
		statusCode int
		want       error
	}{
		{400, ErrBadRequest},
		{401, ErrUnauthorized},
		{403, ErrForbidden},
		{404, ErrNotFound},
		{409, ErrConflict},
		{429, ErrRateLimited},
		{500, ErrServerError},
		{502, ErrBadGateway},
		{503, ErrServiceUnavail},
		{504, ErrGatewayTimeout},
		{418, nil},
	}

	for _, tt := range tests {
		got := sentinelForStatusCode(tt.statusCode)
		if got != tt.want {
			t.Errorf("sentinelForStatusCode(%d) = %v, want %v", tt.statusCode, got, tt.want)
		}
	}
}

func TestSentinelForAPIMessage(t *testing.T) {
	tests := []struct {
		msg  string
		want error
	}{
		{"api.err.Invalid", ErrBadRequest},
		{"api.err.InvalidObject", ErrBadRequest},
		{"api.err.InvalidValue", ErrBadRequest},
		{"api.err.LoginRequired", ErrUnauthorized},
		{"api.err.Unauthorized", ErrUnauthorized},
		{"api.err.NoPermission", ErrForbidden},
		{"api.err.Forbidden", ErrForbidden},
		{"api.err.ObjectNotFound", ErrNotFound},
		{"api.err.NotFound", ErrNotFound},
		{"api.err.ObjectInUse", ErrConflict},
		{"api.err.Conflict", ErrConflict},
		{"api.err.Unknown", nil},
		{"some other error", nil},
		{"", nil},
	}

	for _, tt := range tests {
		got := sentinelForAPIMessage(tt.msg)
		if got != tt.want {
			t.Errorf("sentinelForAPIMessage(%q) = %v, want %v", tt.msg, got, tt.want)
		}
	}
}
