package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &MsgCopyData{}
var _ Frontend = &MsgCopyData{}
var _ Backend = &MsgCopyData{}

type MsgCopyData struct {
	Data []byte
}

func (x *MsgCopyData) message() {}

func (x *MsgCopyData) frontend() {}

func (x *MsgCopyData) backend() {}

func (x *MsgCopyData) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)
	length := sizeMessageLength + sizeData

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindCopyData))
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *MsgCopyData) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindCopyData, b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}

var _ Message = &MsgCopyDone{}
var _ Frontend = &MsgCopyDone{}
var _ Backend = &MsgCopyDone{}

type MsgCopyDone struct{}

func (x *MsgCopyDone) message() {}

func (x *MsgCopyDone) frontend() {}

func (x *MsgCopyDone) backend() {}

func (x *MsgCopyDone) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MessageKindCopyDone))
	buf.AppendInt32(int32(length))
	return buf.Bytes(), nil
}

func (x *MsgCopyDone) UnmarshalBinary(b []byte) error {
	b, err := shiftHeader(MessageKindCopyDone, b)
	if err != nil {
		return invalidFormat(err)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
