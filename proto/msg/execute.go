package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindExecute byte = 'E'

var _ Message = &Execute{}
var _ Frontend = &Execute{}

type Execute struct {
	Portal   string
	RowLimit int32
}

func (x *Execute) message() {}

func (x *Execute) frontend() {}

func (x *Execute) AppendBinary(b []byte) ([]byte, error) {
	const sizeRowLimit = 4

	sizePortal := len(x.Portal) + 1 // null terminated string

	length := sizeMessageLength + sizePortal + sizeRowLimit

	if length > math.MaxInt32 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindExecute)
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Portal)
	buf.AppendInt32(x.RowLimit)
	return buf.Bytes(), nil
}

func (x *Execute) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindExecute {
		return unexpectedKind(kind, KindExecute)
	}

	buf := bytex.NewBuffer(b)

	portal, err := buf.ShiftString()
	if err != nil {
		return invalidFormat(err)
	}

	limit, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	x.Portal = portal
	x.RowLimit = limit
	return nil
}
