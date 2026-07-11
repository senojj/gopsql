package msg

import (
	"gopsql/internal/bytex"
)

const KindBindComplete byte = '2'

var _ Message = &BindComplete{}
var _ Backend = &BindComplete{}

type BindComplete struct{}

func (x *BindComplete) message() {}

func (x *BindComplete) backend() {}

func (x *BindComplete) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindBindComplete)
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *BindComplete) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindBindComplete {
		return unexpectedKind(kind, KindBindComplete)
	}

	if len(b) > 0 {
		return invalidFormat(bytex.ErrValueOverflow)
	}
	return nil
}
