package pgwire

import (
	"fmt"
	"gopsql/pgio"
)

var (
	nullByte = []byte{0}
)

func invalidFormat(cause error) error {
	return fmt.Errorf("%w: %w", ErrInvalidFormat, cause)
}

func unexpectedKind(got byte, want MessageKind) error {
	return fmt.Errorf("%w: got '%d', want '%d'", ErrUnexpectedKind, got, want)
}

func unexpectedAuthKind(got int32, want AuthenticationKind) error {
	return fmt.Errorf("%w: got '%d', want '%d'", ErrUnexpectedKind, got, want)
}

func shiftLength(in []byte) ([]byte, error) {
	length, b, err := pgio.ShiftInt32(in)
	if err != nil {
		return in, err
	}

	size := int(length) - 4

	if size > len(b) {
		return in, pgio.ErrValueUnderflow
	}
	return b[:size], nil
}

func shiftHeader(msg MessageKind, in []byte) ([]byte, error) {
	kind, b, err := pgio.ShiftByte(in)
	if err != nil {
		return in, err
	}

	if !msg.Is(kind) {
		return in, unexpectedKind(kind, msg)
	}

	return shiftLength(b)
}
