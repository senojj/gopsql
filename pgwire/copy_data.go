package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &CopyData{}
var _ Frontend = &CopyData{}
var _ Backend = &CopyData{}

type CopyData struct {
	Data []byte
}

func (x *CopyData) message() {}

func (x *CopyData) frontend() {}

func (x *CopyData) backend() {}

func (x *CopyData) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)
	length := sizeMessageLength + sizeData

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgCopyData))
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *CopyData) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgCopyData, b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}
