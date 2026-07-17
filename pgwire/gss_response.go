package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &GSSResponse{}
var _ Frontend = &GSSResponse{}

type GSSResponse struct {
	Data []byte
}

func (x *GSSResponse) message() {}

func (x *GSSResponse) frontend() {}

func (x *GSSResponse) AppendBinary(b []byte) ([]byte, error) {
	length := sizeMessageLength + len(x.Data)

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}
	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgGSSResponse))
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *GSSResponse) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgGSSResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}
