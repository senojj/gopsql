package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindClose byte = 'C'

var _ Message = &Close{}
var _ Frontend = &Close{}

type Close struct {
	Kind byte
	Name string
}

func (x *Close) message() {}

func (x *Close) frontend() {}

func (x *Close) AppendBinary(b []byte) ([]byte, error) {
	const sizeKind = 1

	sizeName := len(x.Name) + 1 // null terminated string

	length := sizeMessageLength + sizeKind + sizeName

	if length > math.MaxInt32 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindClose)
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Kind)
	buf.AppendString(x.Name)
	return buf.Bytes(), nil
}

func (x *Close) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindClose {
		return unexpectedKind(msgKind, KindClose)
	}

	buf := bytex.NewBuffer(b)

	kind, err := buf.ShiftByte()
	if err != nil {
		return invalidFormat(err)
	}

	name, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}
	x.Kind = kind
	x.Name = name
	return nil
}
