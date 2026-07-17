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

func unexpectedKind(got, want byte) error {
	return fmt.Errorf("%w: got '%d', want '%d'", ErrUnexpectedKind, got, want)
}

func unexpectedAuthKind(got, want int32) error {
	return fmt.Errorf("%w: got '%d', want '%d'", ErrUnexpectedKind, got, want)
}

func ShiftLength(b []byte) ([]byte, error) {
	length, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return nil, err
	}

	size := int(length) - 4

	if size > len(b) {
		return nil, pgio.ErrValueUnderflow
	}
	return b[:size], nil
}

func ShiftHeader(b []byte) (byte, []byte, error) {
	pgwireKind, b, err := pgio.ShiftByte(b)
	if err != nil {
		return 0, nil, err
	}
	b, err = ShiftLength(b)
	return pgwireKind, b, err
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
