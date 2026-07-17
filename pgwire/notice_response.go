package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &NoticeResponse{}
var _ Backend = &NoticeResponse{}

type NoticeResponse struct {
	Fields []byte
	Values []string
}

func (x *NoticeResponse) message() {}

func (x *NoticeResponse) backend() {}

func (x *NoticeResponse) AppendBinary(b []byte) ([]byte, error) {
	countFields := len(x.Fields)

	if countFields != len(x.Values) {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	length := sizeMessageLength + countFields

	for _, value := range x.Values {
		length += len(value) + 1 // null terminated strings
	}
	length += 1 // null terminated list

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgNoticeResponse))
	buf.AppendInt32(int32(length))

	for i := range countFields {
		buf.AppendByte(x.Fields[i])
		buf.AppendString(x.Values[i])
	}
	buf.AppendByte(0)
	return buf.Bytes(), nil
}

func (x *NoticeResponse) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgNoticeResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	field, err := buf.ShiftByte()
	if err != nil {
		return invalidFormat(err)
	}

	var fields []byte
	var values []string

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
