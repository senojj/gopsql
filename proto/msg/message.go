package msg

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"gopsql/internal/bytex"
	"io"
)

const (
	KindAuthentication  byte = 'R'
	KindParseComplete   byte = '1'
	KindPortalSuspended byte = 's'
	KindReadyForQuery   byte = 'Z'
	KindRowDescription  byte = 'T'
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
	FormatText   int8 = 0
	FormatBinary int8 = 1
)

const (
	ColumnFormatText   int16 = 0
	ColumnFormatBinary int16 = 1
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

type MsgParseComplete struct{}

func (x *MsgParseComplete) Encode(w io.Writer) error {
	return writeMessage(w, msgKindParseComplete, []byte{})
}

func (x *MsgParseComplete) Decode(_ []byte) error {
	return nil
}

type MsgPortalSuspended struct{}

func (x *MsgPortalSuspended) Encode(w io.Writer) error {
	return writeMessage(w, msgKindPortalSuspended, []byte{})
}

func (x *MsgPortalSuspended) Decode(_ []byte) error {
	return nil
}

type MsgReadyForQuery struct {
	TxStatus byte
}

func (x *MsgReadyForQuery) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeByte(&buf, x.TxStatus)
	return writeMessage(w, msgKindReadyForQuery, buf.Bytes())
}

func (x *MsgReadyForQuery) Decode(b []byte) error {
	_, err := readByte(b, &x.TxStatus)
	if err != nil {
		return err
	}
	return nil
}

type MsgRowDescription struct {
	Names     []string
	Tables    []int32
	Columns   []int16
	DataTypes []int32
	Sizes     []int16
	Modifiers []int32
	Formats   []int16
}

func (x *MsgRowDescription) Encode(w io.Writer) error {
	var buf bytes.Buffer
	_ = writeInt16(&buf, int16(len(x.Names)))
	for i := range len(x.Names) {
		_ = writeString(&buf, x.Names[i])
		_ = writeInt32(&buf, x.Tables[i])
		_ = writeInt16(&buf, x.Columns[i])
		_ = writeInt32(&buf, x.DataTypes[i])
		_ = writeInt16(&buf, x.Sizes[i])
		_ = writeInt32(&buf, x.Modifiers[i])
		_ = writeInt16(&buf, x.Formats[i])
	}
	return writeMessage(w, msgKindRowDescription, buf.Bytes())
}

func (x *MsgRowDescription) Decode(b []byte) error {
	var length int16
	bread, err := readInt16(b, &length)
	if err != nil {
		return err
	}
	b = b[bread:]

	x.Names = make([]string, length)
	x.Tables = make([]int32, length)
	x.Columns = make([]int16, length)
	x.DataTypes = make([]int32, length)
	x.Sizes = make([]int16, length)
	x.Modifiers = make([]int32, length)
	x.Formats = make([]int16, length)

	for i := range length {
		bread, err := readString(b, &x.Names[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt32(b, &x.Tables[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt16(b, &x.Columns[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt32(b, &x.DataTypes[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt16(b, &x.Sizes[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt32(b, &x.Modifiers[i])
		if err != nil {
			return err
		}
		b = b[bread:]

		bread, err = readInt16(b, &x.Formats[i])
		if err != nil {
			return err
		}
		b = b[bread:]
	}
	return nil
}

type MsgUnknown struct{}

func (x *MsgUnknown) Encode(_ io.Writer) error {
	return ErrUnknownMessageType
}

func (x *MsgUnknown) Decode(_ []byte) error {
	return ErrUnknownMessageType
}

type MsgUnknownAuth struct{}

func (x *MsgUnknownAuth) Encode(_ io.Writer) error {
	return ErrUnknownAuthType
}

func (x *MsgUnknownAuth) Decode(_ []byte) error {
	return ErrUnknownAuthType
}
