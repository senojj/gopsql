package msg

import (
	"gopsql/internal/bytex"
	"math"
	"slices"
)

const KindGSSResponse byte = 'p'

var _ Message = &GSSResponse{}
var _ Frontend = &GSSResponse{}

type GSSResponse struct {
	msg
	front

	Data []byte
}

func (x *GSSResponse) AppendBinary(b []byte) ([]byte, error) {
	length := sizeMessageLength + len(x.Data)

	if length > math.MaxInt32 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}
	size := sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bytex.AppendByte(b, KindGSSResponse)
	b = bytex.AppendInt32(b, int32(length))
	b = bytex.AppendByte(b, x.Data...)
	return b, nil
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
