package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &CommandComplete{}
var _ Backend = &CommandComplete{}

type CommandComplete struct {
	Tag string
}

func (x *CommandComplete) message() {}

func (x *CommandComplete) backend() {}

func (x *CommandComplete) AppendBinary(b []byte) ([]byte, error) {
	sizeTag := len(x.Tag) + 1 // null terminated string
	length := sizeMessageLength + sizeTag

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgCommandComplete))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Tag)
	return buf.Bytes(), nil
}

func (x *CommandComplete) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgCommandComplete, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	tag, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}
	x.Tag = tag
	return nil
}
