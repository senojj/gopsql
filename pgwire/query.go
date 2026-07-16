package pgwire

import "gopsql/pgio"

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

	buf := pgio.NewBuffer(b)

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

	query, b, err := pgio.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}

	x.Value = query
	return nil
}
