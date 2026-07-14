package msg

import (
	"gopsql/internal/bytex"
)

var _ Message = &GSSENCRequest{}
var _ Frontend = &GSSENCRequest{}

const (
	encHigh               int32 = 1234
	encLow                int32 = 5680
	CodeEncryptionRequest int32 = encLow | encHigh<<16
)

type GSSENCRequest struct{}

func (x *GSSENCRequest) message() {}

func (x *GSSENCRequest) frontend() {}

func (x *GSSENCRequest) AppendBinary(b []byte) ([]byte, error) {
	const sizeCode = 4
	const length = sizeMessageLength + sizeCode

	buf := bytex.NewBuffer(b)
	buf.Grow(length)
	buf.AppendInt32(length)
	buf.AppendInt32(CodeEncryptionRequest)
	return buf.Bytes(), nil
}

func (x *GSSENCRequest) UnmarshalBinary(b []byte) error {
	b, err := ShiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}

	code, b, err := bytex.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if code != CodeEncryptionRequest {
		return invalidFormat(bytex.ErrUnknownCode)
	}

	if len(b) > 0 {
		return invalidFormat(bytex.ErrValueOverflow)
	}
	return nil
}
