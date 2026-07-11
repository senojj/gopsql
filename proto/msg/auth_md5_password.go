package msg

import (
	"gopsql/internal/bytex"
)

const KindAuthMD5Password int32 = 5

var _ Message = &AuthMD5Password{}
var _ Backend = &AuthMD5Password{}

type AuthMD5Password struct {
	Salt [4]byte
}

func (x *AuthMD5Password) message() {}

func (x *AuthMD5Password) backend() {}

func (x *AuthMD5Password) AppendBinary(b []byte) ([]byte, error) {
	const sizeSalt = 4
	const length = sizeMessageLength + sizeAuthKind + sizeSalt
	const size = sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthMD5Password)
	buf.AppendByte(x.Salt[:]...)
	return buf.Bytes(), nil
}

func (x *AuthMD5Password) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthMD5Password {
		return unexpectedAuthKind(authKind, KindAuthMD5Password)
	}
	copy(x.Salt[:], b)
	return nil
}
