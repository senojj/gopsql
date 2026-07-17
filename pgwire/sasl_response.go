package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &SASLResponse{}
var _ Frontend = &SASLResponse{}

type SASLResponse struct {
	Data []byte
}

func (x *SASLResponse) message() {}

func (x *SASLResponse) frontend() {}

func (x *SASLResponse) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)

	length := sizeMessageLength + sizeData

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MsgSASLResponse))
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *SASLResponse) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgSASLResponse, b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}
