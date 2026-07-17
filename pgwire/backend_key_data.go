package pgwire

import (
	"gopsql/pgio"
	"math"
)

var _ Message = &BackendKeyData{}
var _ Backend = &BackendKeyData{}

type BackendKeyData struct {
	ProcessID int32
	SecretKey []byte
}

func (x *BackendKeyData) message() {}

func (x *BackendKeyData) backend() {}

func (x *BackendKeyData) AppendBinary(b []byte) ([]byte, error) {
	const sizeProcessID = 4
	sizeSecretKey := len(x.SecretKey)

	if sizeSecretKey < 4 {
		return b, invalidFormat(pgio.ErrValueUnderflow)
	}

	if sizeSecretKey > 256 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	length := sizeMessageLength + sizeProcessID + sizeSecretKey

	if length > math.MaxInt32 {
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgBackendKeyData))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(x.ProcessID)
	buf.AppendByte(x.SecretKey...)
	return buf.Bytes(), nil
}

func (x *BackendKeyData) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgBackendKeyData, b)
	if err != nil {
		return invalidFormat(err)
	}

	buf := pgio.NewBuffer(b)

	processID, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	if buf.Len() < 4 {
		return invalidFormat(pgio.ErrValueUnderflow)
	}

	if buf.Len() > 256 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	secretKey := make([]byte, buf.Len())
	copy(secretKey, buf.Bytes())

	x.ProcessID = processID
	x.SecretKey = secretKey
	return nil
}
