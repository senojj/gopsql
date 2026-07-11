package msg

import (
	"gopsql/internal/bytex"
	"math"
)

const KindAuthSASLFinal int32 = 12

var _ Message = &AuthSASLFinal{}
var _ Backend = &AuthSASLFinal{}

type AuthSASLFinal struct {
	Data []byte
}

func (x *AuthSASLFinal) message() {}

func (x *AuthSASLFinal) backend() {}

func (x *AuthSASLFinal) AppendBinary(b []byte) ([]byte, error) {
	sizeData := len(x.Data)

	length := sizeMessageLength + sizeAuthKind + sizeData

	if length > math.MaxInt32 {
		return nil, invalidFormat(bytex.ErrValueOverflow)
	}

	size := sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthSASLFinal)
	buf.AppendByte(x.Data...)
	return buf.Bytes(), nil
}

func (x *AuthSASLFinal) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bytex.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthSASLFinal {
		return unexpectedAuthKind(authKind, KindAuthSASLFinal)
	}
	x.Data = make([]byte, len(b))
	copy(x.Data, b)
	return nil
}
