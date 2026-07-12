package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindCommandComplete byte = 'C'

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
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindCommandComplete)
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Tag)
	return buf.Bytes(), nil
}

func (x *CommandComplete) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindCommandComplete {
		return unexpectedKind(kind, KindCommandComplete)
	}

	buf := bytex.NewBuffer(b)

	tag, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}
	x.Tag = tag
	return nil
}
