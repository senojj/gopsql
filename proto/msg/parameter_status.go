package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindParameterStatus byte = 'S'

var _ Message = &ParameterStatus{}
var _ Backend = &ParameterStatus{}

type ParameterStatus struct {
	Name  string
	Value string
}

func (x *ParameterStatus) message() {}

func (x *ParameterStatus) backend() {}

func (x *ParameterStatus) AppendBinary(b []byte) ([]byte, error) {
	sizeName := len(x.Name) + 1   // null terminated string
	sizeValue := len(x.Value) + 1 // null terminated string

	length := sizeMessageLength +
		sizeName +
		sizeValue

	if length > math.MaxInt32 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(KindParameterStatus)
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Name)
	buf.AppendString(x.Value)
	return buf.Bytes(), nil
}

func (x *ParameterStatus) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindParameterStatus {
		return unexpectedKind(kind, KindParameterStatus)
	}

	buf := bytex.NewBuffer(b)

	name, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	value, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	x.Name = name
	x.Value = value
	return nil
}
