package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindDescribe byte = 'D'

var _ Message = &Describe{}
var _ Frontend = &Describe{}

type Describe struct {
	Kind byte
	Name string
}

func (x *Describe) message() {}

func (x *Describe) frontend() {}

func (x *Describe) AppendBinary(b []byte) ([]byte, error) {
	const sizeKind = 1

	length := sizeMessageLength +
		sizeKind +
		len(x.Name) + 1 // null terminated string

	if length > math.MaxInt32 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindDescribe)
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Kind)
	buf.AppendString(x.Name)
	return buf.Bytes(), nil
}

func (x *Describe) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindDescribe {
		return unexpectedKind(msgKind, KindDescribe)
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
