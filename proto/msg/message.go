package msg

import (
	"encoding"
	"errors"
	"fmt"
	"gopsql/internal/bytex"
)

const (
	KindAuthentication byte = 'R'
)

const (
	FieldSeverity         byte = 'S'
	FieldSeverityRaw      byte = 'V'
	FieldCode             byte = 'C'
	FieldMessage          byte = 'M'
	FieldDetail           byte = 'D'
	FieldHint             byte = 'H'
	FieldPosition         byte = 'P'
	FieldInternalPosition byte = 'p'
	FieldInternalQuery    byte = 'q'
	FieldWhere            byte = 'W'
	FieldSchema           byte = 's'
	FieldTable            byte = 't'
	FieldColumn           byte = 'c'
	FieldDataType         byte = 'd'
	FieldConstraint       byte = 'n'
	FieldFile             byte = 'F'
	FieldLine             byte = 'L'
	FieldRoutine          byte = 'R'
)

const (
	FormatText8   int8 = 0
	FormatBinary8 int8 = 1
)

const (
	FormatText16   int16 = int16(FormatText8)
	FormatBinary16 int16 = int16(FormatBinary8)
)

const (
	TxStatusIdle   byte = 'I'
	TxStatusActive byte = 'T'
	TxStatusError  byte = 'E'
)

const (
	sizeMessageKind   = 1
	sizeMessageLength = 4
	sizeAuthKind      = 4
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
	length, b, err := bytex.ShiftInt32(b)
	if err != nil {
		return nil, err
	}

	size := int(length) - 4

	if size > len(b) {
		return nil, bytex.ErrValueUnderflow
	}
	return b[:size], nil
}

func ShiftHeader(b []byte) (byte, []byte, error) {
	msgKind, b, err := bytex.ShiftByte(b)
	if err != nil {
		return 0, nil, err
	}
	b, err = ShiftLength(b)
	return msgKind, b, err
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
