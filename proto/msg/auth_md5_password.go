package msg

import (
	"gopsql/internal/bx"
	"slices"
)

const KindAuthMD5Password int32 = 5

var _ Message = &AuthMD5Password{}
var _ Backend = &AuthMD5Password{}

type AuthMD5Password struct {
	msg
	back

	Salt [4]byte
}

func (x *AuthMD5Password) AppendBinary(b []byte) ([]byte, error) {
	const sizeSalt = 4
	const length = sizeMessageLength + sizeAuthKind + sizeSalt
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthMD5Password)
	b = bx.AppendByte(b, x.Salt[:]...)
	return b, nil
}

func (x *AuthMD5Password) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bx.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthMD5Password {
		return unexpectedAuthKind(authKind, KindAuthMD5Password)
	}
	copy(x.Salt[:], b)
	return nil
}
