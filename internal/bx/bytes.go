package bx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"unsafe"
)

var (
	ErrValueUnderflow     = errors.New("partial value")
	ErrValueOverflow      = errors.New("value too large")
	ErrUnknownMessageType = errors.New("unknown message type")
	ErrUnknownAuthType    = errors.New("unknown authentication type")
	ErrUnknownCode        = errors.New("unknown code")
)

func ShiftByte(b []byte) (byte, []byte, error) {
	if len(b) == 0 {
		return 0, nil, io.EOF
	}
	return b[0], b[1:], nil
}

func ShiftBytes(b []byte, length int) ([]byte, []byte, error) {
	if len(b) < length {
		return nil, nil, ErrValueUnderflow
	}
	output := make([]byte, length)
	copy(output, b[:length])
	return output, b[length:], nil
}

func ShiftInt8(b []byte) (int8, []byte, error) {
	v, b, err := ShiftByte(b)
	if err != nil {
		return 0, nil, err
	}
	return int8(v), b, nil
}

func ShiftInt16(b []byte) (int16, []byte, error) {
	if len(b) < 2 {
		return 0, nil, ErrValueUnderflow
	}
	i := int16(binary.BigEndian.Uint16(b))
	return i, b[2:], nil
}

func ShiftInt32(b []byte) (int32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, ErrValueUnderflow
	}
	i := int32(binary.BigEndian.Uint32(b))
	return i, b[4:], nil
}

var zero []byte = []byte{0}

func ShiftString(b []byte) (string, []byte, error) {
	s, b, found := bytes.Cut(b, zero)
	if found {
		return unsafe.String(unsafe.SliceData(s), len(s)), b, nil
	}
	return "", nil, ErrValueUnderflow
}

func AppendByte(b []byte, i ...byte) []byte {
	return append(b, i...)
}

func AppendInt8(b []byte, i ...int8) []byte {
	b = slices.Grow(b, len(i))
	for _, v := range i {
		b = append(b, byte(v))
	}
	return b
}

func AppendInt16(b []byte, i ...int16) []byte {
	b = slices.Grow(b, len(i))
	for _, v := range i {
		b = binary.BigEndian.AppendUint16(b, uint16(v))
	}
	return b
}

func AppendInt32(b []byte, i ...int32) []byte {
	b = slices.Grow(b, len(i))
	for _, v := range i {
		b = binary.BigEndian.AppendUint32(b, uint32(v))
	}
	return b
}

func AppendInt64(b []byte, i ...int64) []byte {
	b = slices.Grow(b, len(i))
	for _, v := range i {
		b = binary.BigEndian.AppendUint64(b, uint64(v))
	}
	return b
}

func AppendString(b []byte, s ...string) []byte {
	for _, v := range s {
		b = append(b, []byte(v)...)
		b = append(b, 0)
	}
	return b
}
