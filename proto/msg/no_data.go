package msg

import (
	"gopsql/internal/bytex"
)

const KindNoData byte = 'n'

var _ Message = &NoData{}
var _ Backend = &NoData{}

type NoData struct{}

func (x *NoData) message() {}

func (x *NoData) backend() {}

func (x *NoData) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindNoData)
	buf.AppendInt32(length)
	return buf.Bytes(), nil
}

func (x *NoData) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindNoData {
		return unexpectedKind(kind, KindNoData)
	}

	if len(b) > 0 {
		return invalidFormat(bytex.ErrValueOverflow)
	}
	return nil
}
