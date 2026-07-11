package msg

import (
	"gopsql/internal/bytex"
	"slices"
)

const KindNoData byte = 'n'

var _ Message = &NoData{}
var _ Backend = &NoData{}

type NoData struct {
	msg
	back
}

func (x *NoData) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bytex.AppendByte(b, KindNoData)
	b = bytex.AppendInt32(b, length)
	return b, nil
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
