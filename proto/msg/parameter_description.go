package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindParameterDescription byte = 't'

var _ Message = &ParameterDescription{}
var _ Backend = &ParameterDescription{}

type ParameterDescription struct {
	Parameters []int32
}

func (x *ParameterDescription) message() {}

func (x *ParameterDescription) backend() {}

func (x *ParameterDescription) AppendBinary(b []byte) ([]byte, error) {
	const sizeParameterCount = 2
	const sizeParameter = 4

	countParameter := len(x.Parameters)

	length := sizeMessageLength +
		sizeParameterCount +
		sizeParameter*countParameter

	if length > math.MaxInt32 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindParameterDescription)
	buf.AppendInt32(int32(length))
	buf.AppendInt16(int16(countParameter))

	for i := range countParameter {
		buf.AppendInt32(x.Parameters[i])
	}
	return buf.Bytes(), nil
}

func (x *ParameterDescription) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindParameterDescription {
		return unexpectedKind(kind, KindParameterDescription)
	}

	buf := bytex.NewBuffer(b)

	countParameters, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}

	parameters := make([]int32, 0, countParameters)
	for range countParameters {
		parameter, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}
		parameters = append(parameters, parameter)
	}
	x.Parameters = parameters
	return nil
}
