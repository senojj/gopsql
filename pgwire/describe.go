package pgwire

import (
	"gopsql/pgio"
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
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindDescribe)
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Kind)
	buf.AppendString(x.Name)
	return buf.Bytes(), nil
}

func (x *Describe) UnmarshalBinary(b []byte) error {
	pgwireKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if pgwireKind != KindDescribe {
		return unexpectedKind(pgwireKind, KindDescribe)
	}

	buf := pgio.NewBuffer(b)

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
