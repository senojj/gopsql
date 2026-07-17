package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &CloseComplete{}
var _ Backend = &CloseComplete{}

type CloseComplete struct{}

func (x *CloseComplete) message() {}

func (x *CloseComplete) backend() {}

func (x *CloseComplete) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgCloseComplete))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *CloseComplete) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgCloseComplete, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
