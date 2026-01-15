// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// errorCauseCode is a cause code that appears in either an ERROR or ABORT chunk (RFC 9260 section 3.3.10).
type errorCauseCode uint16

type errorCause interface {
	unmarshal([]byte) error
	marshal() ([]byte, error)
	length() uint16
	String() string

	errorCauseCode() errorCauseCode
}

// Errors for building/validating error causes.
var (
	ErrBuildErrorCaseHandle = errors.New("buildErrorCause does not handle this cause code")
	ErrCauseTooShort        = errors.New("error cause too short")
	ErrCauseLengthInvalid   = errors.New("error cause length invalid")
)

// buildErrorCause delegates building an error cause from raw bytes to the correct structure.
// Validates the generic error-cause header (code + length) before dispatch.
func buildErrorCause(raw []byte) (errorCause, error) {
	if len(raw) < 4 {
		return nil, ErrCauseTooShort
	}

	clen := int(binary.BigEndian.Uint16(raw[2:]))
	if clen < 4 || clen > len(raw) {
		return nil, ErrCauseLengthInvalid
	}

	var errCause errorCause

	c := errorCauseCode(binary.BigEndian.Uint16(raw[0:]))
	switch c {
	case invalidMandatoryParameter:
		errCause = &errorCauseInvalidMandatoryParameter{}
	case unrecognizedChunkType:
		errCause = &errorCauseUnrecognizedChunkType{}
	case protocolViolation:
		errCause = &errorCauseProtocolViolation{}
	case userInitiatedAbort:
		errCause = &errorCauseUserInitiatedAbort{}
	default:
		// Unknown or unimplemented cause codes return a clear error.
		return nil, fmt.Errorf("%w: %s", ErrBuildErrorCaseHandle, c.String())
	}

	if err := errCause.unmarshal(raw[:clen]); err != nil {
		return nil, err
	}

	return errCause, nil
}

// RFC 9260 section 3.3.10 "Error Causes".
const (
	invalidStreamIdentifier                errorCauseCode = 1
	missingMandatoryParameter              errorCauseCode = 2
	staleCookieError                       errorCauseCode = 3
	outOfResource                          errorCauseCode = 4
	unresolvableAddress                    errorCauseCode = 5
	unrecognizedChunkType                  errorCauseCode = 6
	invalidMandatoryParameter              errorCauseCode = 7
	unrecognizedParameters                 errorCauseCode = 8
	noUserData                             errorCauseCode = 9
	cookieReceivedWhileShuttingDown        errorCauseCode = 10
	restartOfAnAssociationWithNewAddresses errorCauseCode = 11
	userInitiatedAbort                     errorCauseCode = 12
	protocolViolation                      errorCauseCode = 13
)

func (e errorCauseCode) String() string { //nolint:cyclop
	switch e {
	case invalidStreamIdentifier:
		return "Invalid Stream Identifier"
	case missingMandatoryParameter:
		return "Missing Mandatory Parameter"
	case staleCookieError:
		return "Stale Cookie Error"
	case outOfResource:
		return "Out of Resource"
	case unresolvableAddress:
		return "Unresolvable Address"
	case unrecognizedChunkType:
		return "Unrecognized Chunk Type"
	case invalidMandatoryParameter:
		return "Invalid Mandatory Parameter"
	case unrecognizedParameters:
		return "Unrecognized Parameters"
	case noUserData:
		return "No User Data"
	case cookieReceivedWhileShuttingDown:
		return "Cookie Received While Shutting Down"
	case restartOfAnAssociationWithNewAddresses:
		return "Restart of an Association with New Addresses"
	case userInitiatedAbort:
		return "User Initiated Abort"
	case protocolViolation:
		return "Protocol Violation"
	default:
		return fmt.Sprintf("Unknown CauseCode: %d", e)
	}
}
