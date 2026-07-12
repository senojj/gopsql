package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindPasswordMessage byte = 'p'

var _ Message = &PasswordMessage{}
var _ Frontend = &PasswordMessage{}

type PasswordMessage struct {
	Password string
}

func (x *PasswordMessage) message() {}

func (x *PasswordMessage) frontend() {}

func (x *PasswordMessage) AppendBinary(b []byte) ([]byte, error) {
	sizePassword := len(x.Password) + 1 // null terminated string

	length := sizeMessageLength + sizePassword

	if length > math.MaxInt32 {
		return b, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(KindPasswordMessage)
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Password)
	return buf.Bytes(), nil
}

func (x *PasswordMessage) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != KindPasswordMessage {
		return unexpectedKind(kind, KindPasswordMessage)
	}

	password, b, err := bytex.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Password = password
	return nil
}
