package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindGSSResponse byte = 'p'

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
		return b, invalidFormat(bytex.ErrValueOverflow)
	}
	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindGSSResponse)
	buf.AppendInt32(int32(length))
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *GSSResponse) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindGSSResponse {
		return unexpectedKind(kind, KindGSSResponse)
	}

	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}
