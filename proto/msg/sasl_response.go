package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindSASLResponse byte = 'p'

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
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(KindSASLResponse)
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *SASLResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindSASLResponse {
		return unexpectedKind(kind, KindSASLResponse)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}
