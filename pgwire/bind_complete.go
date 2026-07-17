package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &BindComplete{}
var _ Backend = &BindComplete{}

type BindComplete struct{}

func (x *BindComplete) message() {}

func (x *BindComplete) backend() {}

func (x *BindComplete) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgBindComplete))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *BindComplete) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgBindComplete, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
