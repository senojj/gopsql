package pgwire

import (
	"gopsql/pgio"
	"math"
)

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
		return b, invalidFormat(pgio.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := pgio.NewBuffer(b)

	buf.Grow(size)
	buf.AppendByte(byte(MsgPasswordMessage))
	buf.AppendInt32(int32(length))
	buf.AppendString(x.Password)
	return buf.Bytes(), nil
}

func (x *PasswordMessage) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgPasswordMessage, b)
	if err != nil {
		return invalidFormat(err)
	}

	password, b, err := pgio.ShiftString(b)
	if err != nil {
		return invalidFormat(err)
	}

	x.Password = password
	return nil
}
