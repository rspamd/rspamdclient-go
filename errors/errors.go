// Package errors provides error handling for the Rspamd API client
package errors

import "fmt"

// RspamdError represents the different types of errors that can occur
type RspamdError struct {
	Type    ErrorType
	Message string
	Cause   error
}

// ErrorType represents the type of error
type ErrorType int

const (
	HTTPError ErrorType = iota
	SerdeError
	ConfigError
	UnknownError
	IOError
	ParseError
	EncryptionError
	UTF8Error
	InvalidHeaderValue
	InvalidHeaderName
)

// Error implements the error interface
func (e *RspamdError) Error() string {
	switch e.Type {
	case HTTPError:
		return fmt.Sprintf("HTTP request failed: %s", e.Message)
	case SerdeError:
		return fmt.Sprintf("Serialization/Deserialization error: %s", e.Message)
	case ConfigError:
		return fmt.Sprintf("Configuration error: %s", e.Message)
	case IOError:
		return fmt.Sprintf("IO error: %s", e.Message)
	case ParseError:
		return fmt.Sprintf("URL parsing error: %s", e.Message)
	case EncryptionError:
		return fmt.Sprintf("Encryption error: %s", e.Message)
	case UTF8Error:
		return fmt.Sprintf("UTF8 process error: %s", e.Message)
	case InvalidHeaderValue:
		return fmt.Sprintf("Invalid HTTP header value: %s", e.Message)
	case InvalidHeaderName:
		return fmt.Sprintf("Invalid HTTP header name: %s", e.Message)
	case UnknownError:
		return "Unknown error"
	default:
		return fmt.Sprintf("Unknown error: %s", e.Message)
	}
}

// Unwrap returns the underlying cause error
func (e *RspamdError) Unwrap() error {
	return e.Cause
}

// NewHTTPError creates a new HTTP error
func NewHTTPError(message string) *RspamdError {
	return &RspamdError{
		Type:    HTTPError,
		Message: message,
	}
}

// NewHTTPErrorWithCause creates a new HTTP error with a cause
func NewHTTPErrorWithCause(message string, cause error) *RspamdError {
	return &RspamdError{
		Type:    HTTPError,
		Message: message,
		Cause:   cause,
	}
}

// NewSerdeError creates a new serialization/deserialization error
func NewSerdeError(cause error) *RspamdError {
	return &RspamdError{
		Type:    SerdeError,
		Message: cause.Error(),
		Cause:   cause,
	}
}

// NewConfigError creates a new configuration error
func NewConfigError(message string) *RspamdError {
	return &RspamdError{
		Type:    ConfigError,
		Message: message,
	}
}

// NewIOError creates a new IO error
func NewIOError(cause error) *RspamdError {
	return &RspamdError{
		Type:    IOError,
		Message: cause.Error(),
		Cause:   cause,
	}
}

// NewParseError creates a new URL parsing error
func NewParseError(cause error) *RspamdError {
	return &RspamdError{
		Type:    ParseError,
		Message: cause.Error(),
		Cause:   cause,
	}
}

// NewEncryptionError creates a new encryption error
func NewEncryptionError(message string) *RspamdError {
	return &RspamdError{
		Type:    EncryptionError,
		Message: message,
	}
}

// NewUTF8Error creates a new UTF8 error
func NewUTF8Error(cause error) *RspamdError {
	return &RspamdError{
		Type:    UTF8Error,
		Message: cause.Error(),
		Cause:   cause,
	}
}

// NewInvalidHeaderValueError creates a new invalid header value error
func NewInvalidHeaderValueError(cause error) *RspamdError {
	return &RspamdError{
		Type:    InvalidHeaderValue,
		Message: cause.Error(),
		Cause:   cause,
	}
}

// NewInvalidHeaderNameError creates a new invalid header name error
func NewInvalidHeaderNameError(cause error) *RspamdError {
	return &RspamdError{
		Type:    InvalidHeaderName,
		Message: cause.Error(),
		Cause:   cause,
	}
}

// NewUnknownError creates a new unknown error
func NewUnknownError() *RspamdError {
	return &RspamdError{
		Type:    UnknownError,
		Message: "",
	}
}
