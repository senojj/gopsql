package msg

import (
	"gopsql/internal/bytex"
)

var _ Message = &CancelRequest{}
var _ Frontend = &CancelRequest{}

const (
	cancelHigh        int32 = 1234
	cancelLow         int32 = 5678
	CodeCancelRequest int32 = cancelLow | cancelHigh<<16
)

type CancelRequest struct {
	ProcessID int32
	SecretKey []byte
}

func (x *CancelRequest) message() {}

func (x *CancelRequest) frontend() {}

func (x *CancelRequest) AppendBinary(b []byte) ([]byte, error) {
	const sizeCode = 4
	const sizeProcessID = 4

	sizeSecretKey := len(x.SecretKey)

	if sizeSecretKey > 256 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	if sizeSecretKey < 4 {
		return nil, invalidFormat(bytex.ErrValueUnderflow)
	}

	length := sizeMessageLength +
		sizeCode +
		sizeProcessID +
		sizeSecretKey

	buf := bytex.NewBuffer(b)
	buf.Grow(length)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(CodeCancelRequest)
	buf.AppendInt32(x.ProcessID)
	buf.AppendByte(x.SecretKey...)
	return buf.Bytes(), nil
}

func (x *CancelRequest) UnmarshalBinary(b []byte) error {
	b, err := ShiftLength(b)
	if err != nil {
		return invalidFormat(err)
	}
	processID, b, err := bytex.ShiftInt32(b)
	if err != nil {
		return err
	}
	x.ProcessID = processID
	x.SecretKey = make([]byte, len(b))
	copy(x.SecretKey, b)
	return nil
}
