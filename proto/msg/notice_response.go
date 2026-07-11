package msg

import (
	"gopsql/internal/bytex"
	"math"
	"slices"
)

const KindNoticeResponse byte = 'N'

var _ Message = &NoticeResponse{}
var _ Backend = &NoticeResponse{}

type NoticeResponse struct {
	msg
	back

	Fields []byte
	Values []string
}

func (x *NoticeResponse) AppendBinary(b []byte) ([]byte, error) {
	countFields := len(x.Fields)

	if countFields != len(x.Values) {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	length := sizeMessageLength + countFields

	for _, value := range x.Values {
		length += len(value) + 1 // null terminated strings
	}
	length += 1 // null terminated list

	if length > math.MaxInt32 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bytex.AppendByte(b, KindNoticeResponse)
	b = bytex.AppendInt32(b, int32(length))

	for i := range countFields {
		b = bytex.AppendByte(b, x.Fields[i])
		b = bytex.AppendString(b, x.Values[i])
	}
	b = bytex.AppendByte(b, 0)
	return b, nil
}

func (x *NoticeResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindNoticeResponse {
		return unexpectedKind(kind, KindNoticeResponse)
	}

	field, b, err := bytex.ShiftByte(b)
	if err != nil {
		return invalidFormat(err)
	}

	var fields []byte
	var values []string

	for field != 0 {
		fields = append(fields, field)

		var value string
		value, b, err = bytex.ShiftString(b)
		if err != nil {
			return invalidFormat(err)
		}
		values = append(values, value)

		field, b, err = bytex.ShiftByte(b)
		if err != nil {
			return invalidFormat(err)
		}
	}
	x.Fields = fields
	x.Values = values
	return nil
}
