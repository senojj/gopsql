package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &CopyDone{}
var _ Frontend = &CopyDone{}
var _ Backend = &CopyDone{}

type CopyDone struct{}

func (x *CopyDone) message() {}

func (x *CopyDone) frontend() {}

func (x *CopyDone) backend() {}

func (x *CopyDone) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgCopyDone))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *CopyDone) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgCopyDone, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
