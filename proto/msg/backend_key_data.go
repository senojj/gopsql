package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindBackendKeyData byte = 'K'

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
		return nil, invalidFormat(bytex.ErrValueUnderflow)
	}

	if sizeSecretKey > 256 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	length := sizeMessageLength + sizeProcessID + sizeSecretKey

	if length > math.MaxInt32 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindBackendKeyData)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(x.ProcessID)
	buf.AppendByte(x.SecretKey...)
	return buf.Bytes(), nil
}

func (x *BackendKeyData) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindBackendKeyData {
		return unexpectedKind(kind, KindBackendKeyData)
	}

	buf := bytex.NewBuffer(b)

	processID, err := buf.ShiftInt32()
	if err != nil {
		return invalidFormat(err)
	}

	if buf.Len() < 4 {
		return invalidFormat(bytex.ErrValueUnderflow)
	}

	if buf.Len() > 256 {
		return invalidFormat(bytex.ErrValueOverflow)
	}
	secretKey := make([]byte, buf.Len())
	copy(secretKey, buf.Bytes())

	x.ProcessID = processID
	x.SecretKey = secretKey
	return nil
}
