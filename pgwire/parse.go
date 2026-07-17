package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &Parse{}
var _ Frontend = &Parse{}

type Parse struct {
	ParameterDataTypes       []int32
	DestinationStatementName string
	Query                    string
}

func (x *Parse) message() {}

func (x *Parse) frontend() {}

func (x *Parse) AppendBinary(b []byte) ([]byte, error) {
	const sizeParameterDataType = 4
	const sizeParameterDataTypeCount = 2

	sizeDestinationStatementName := len(x.DestinationStatementName) + 1 // null terminated string
	sizeQuery := len(x.Query) + 1                                       // null terminated string

	countParameterDataTypes := len(x.ParameterDataTypes)

	if countParameterDataTypes > math.MaxInt16 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	length := sizeMessageLength +
		sizeDestinationStatementName +
		sizeQuery +
		sizeParameterDataTypeCount +
		countParameterDataTypes*sizeParameterDataType

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MsgParse))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.DestinationStatementName)
	buf.AppendString(x.Query)
	buf.AppendInt16(int16(countParameterDataTypes))

	for i := range countParameterDataTypes {
		buf.AppendInt32(x.ParameterDataTypes[i])
	}
	return buf.Bytes(), nil
}

func (x *Parse) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgParse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	destinationStatementName, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	query, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	countParameterDataTypes, err := buf.ShiftInt16()
	if err != nil {
		return invalidFormat(err)
	}

	parameterDataTypes := make([]int32, 0, countParameterDataTypes)

	for range countParameterDataTypes {
		parameterDataType, err := buf.ShiftInt32()
		if err != nil {
			return invalidFormat(err)
		}
		parameterDataTypes = append(parameterDataTypes, parameterDataType)
	}

	x.DestinationStatementName = destinationStatementName
	x.Query = query
	x.ParameterDataTypes = parameterDataTypes
	return nil
}
