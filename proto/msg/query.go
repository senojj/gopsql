package msg

import "gopsql/internal/bytex"

const KindQuery byte = 'Q'

var _ Message = &Query{}
var _ Frontend = &Query{}

type Query struct {
	Value string
}

func (x *Query) message() {}

func (x *Query) frontend() {}

func (x *Query) AppendBinary(b []byte) ([]byte, error) {
	sizeQuery := len(x.Value)

	length := sizeMessageLength + sizeQuery

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(KindQuery)
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Value)
	return buf.Bytes(), nil
}

func (x *Query) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindQuery {
		return unexpectedKind(kind, KindQuery)
	}

	query, b, err := bytex.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(bytex.ErrValueOverflow)
	}

	x.Value = query
	return nil
}
