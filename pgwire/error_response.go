package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &ErrorResponse{}
var _ Backend = &ErrorResponse{}

type ErrorResponse struct {
	Fields []byte
	Values []string
}

func (x *ErrorResponse) message() {}

func (x *ErrorResponse) backend() {}

func (x *ErrorResponse) AppendBinary(b []byte) ([]byte, error) {
	const sizeField = 1

	countFields := len(x.Fields)
	countValues := len(x.Values)

	sizeFields := countFields * sizeField

	length := sizeMessageLength + sizeFields

	for i := range countValues {
		value := x.Values[i]
		length += len(value) + 1 // null terminated string
	}

	length += 1 // null terminated list

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgErrorResponse))
	buf.AppendInt32(int32(length))

	for i := range countFields {
		buf.AppendByte(x.Fields[i])
		buf.AppendString(x.Values[i])
	}
	buf.AppendByte(0)
	return b, nil
}

func (x *ErrorResponse) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgErrorResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	var fields []byte
	var values []string

	field, err := buf.ShiftByte()
	if err != nil {
		return invalidFormat(err)
	}

	for field != 0 {
		fields = append(fields, field)

		value, err := buf.ShiftString()
		if err != nil {
			return invalidFormat(err)
		}
		values = append(values, value)

		field, err = buf.ShiftByte()
		if err != nil {
			return invalidFormat(err)
		}
	}

	x.Fields = fields
	x.Values = values
	return nil
}
