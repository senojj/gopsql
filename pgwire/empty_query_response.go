package pgwire

import (
	"gopsql/pgio"
)

const KindEmptyQueryResponse byte = 'I'

var _ Message = &EmptyQueryResponse{}
var _ Backend = &EmptyQueryResponse{}

type EmptyQueryResponse struct{}

func (x *EmptyQueryResponse) message() {}

func (x *EmptyQueryResponse) backend() {}

func (x *EmptyQueryResponse) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindEmptyQueryResponse)
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *EmptyQueryResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindEmptyQueryResponse {
		return unexpectedKind(kind, KindEmptyQueryResponse)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
