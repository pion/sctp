package sctp

import (
	"fmt"
)

// errorCauseUserInitiatedAbort represents an SCTP error cause
type errorCauseUserInitiatedAbort struct {
	errorCauseHeader
	upperLayerAbortReason []byte
}

func (e *errorCauseUserInitiatedAbort) marshal() ([]byte, error) {
	e.code = userInitiatedAbort
	e.errorCauseHeader.raw = e.upperLayerAbortReason
	return e.errorCauseHeader.marshal()
}

func (e *errorCauseUserInitiatedAbort) unmarshal(raw []byte) error {
	err := e.errorCauseHeader.unmarshal(raw)
	if err != nil {
		return err
	}

	e.upperLayerAbortReason = e.errorCauseHeader.raw
	return nil
}

// String makes errorCauseUserInitiatedAbort printable
func (e *errorCauseUserInitiatedAbort) String() string {
	return fmt.Sprintf("%s: %s", e.errorCauseHeader.String(), e.upperLayerAbortReason)
}
