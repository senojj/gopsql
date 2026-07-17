package pgwire

import (
	"encoding"
	"errors"
	"fmt"
	"gopsql/pgio"
)

var (
	NullByte = []byte{0}
)

var (
	ErrInvalidFormat  = errors.New("invalid format")
	ErrUnexpectedKind = errors.New("unexpected kind")
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

func ShiftLength(in []byte) ([]byte, error) {
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

func ShiftHeader(msg MessageKind, in []byte) ([]byte, error) {
	kind, b, err := pgio.ShiftByte(in)
	if err != nil {
		return in, err
	}

	if !msg.Is(kind) {
		return in, unexpectedKind(kind, msg)
	}

	return ShiftLength(b)
}

type Message interface {
	encoding.BinaryAppender
	encoding.BinaryUnmarshaler

	message()
}

type Backend interface {
	Message

	backend()
}

type Frontend interface {
	Message

	frontend()
}
