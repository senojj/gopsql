package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &Flush{}
var _ Frontend = &Flush{}

type Flush struct{}

func (x *Flush) message() {}

func (x *Flush) frontend() {}

func (x *Flush) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgFlush))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *Flush) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgFlush, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
