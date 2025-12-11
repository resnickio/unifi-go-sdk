package unifi

import (
	"errors"
	"fmt"
)

var (
	ErrBadRequest   = errors.New("bad request")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrRateLimited  = errors.New("rate limited")
	ErrServerError  = errors.New("server error")
	ErrBadGateway   = errors.New("bad gateway")
)

func sentinelForStatusCode(statusCode int) error {
	switch statusCode {
	case 400:
		return ErrBadRequest
	case 401:
		return ErrUnauthorized
	case 403:
		return ErrForbidden
	case 404:
		return ErrNotFound
	case 409:
		return ErrConflict
	case 429:
		return ErrRateLimited
	case 500:
		return ErrServerError
	case 502:
		return ErrBadGateway
	default:
		return nil
	}
}

type APIError struct {
	StatusCode       int
	Message          string
	RetryAfterHeader string
	Err              error
}

func (e *APIError) Error() string {
	return fmt.Sprintf("unifi api error (status %d): %s", e.StatusCode, e.Message)
}

func (e *APIError) Unwrap() error {
	return e.Err
}
