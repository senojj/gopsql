package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &NoData{}
var _ Backend = &NoData{}

type NoData struct{}

func (x *NoData) message() {}

func (x *NoData) backend() {}

func (x *NoData) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgNoData))
	buf.AppendInt32(length)
	return buf.Bytes(), nil
}

func (x *NoData) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgNoData, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
