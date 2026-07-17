package pgwire

import (
	"gopsql/pgio"
	"math"
)

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
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgExecute))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Portal)
	buf.AppendInt32(x.RowLimit)
	return buf.Bytes(), nil
}

func (x *Execute) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgExecute, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

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
