package pgwire

import (
	"gopsql/pgio"
)

const KindAuthMD5Password int32 = 5

var _ Message = &AuthenticationMD5Password{}
var _ Backend = &AuthenticationMD5Password{}

type AuthenticationMD5Password struct {
	Salt [4]byte
}

func (x *AuthenticationMD5Password) message() {}

func (x *AuthenticationMD5Password) backend() {}

func (x *AuthenticationMD5Password) AppendBinary(b []byte) ([]byte, error) {
	const sizeSalt = 4
	const length = sizeMessageLength + sizeAuthKind + sizeSalt
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthMD5Password)
	buf.AppendByte(x.Salt[:]...)
	return buf.Bytes(), nil
}

func (x *AuthenticationMD5Password) UnmarshalBinary(b []byte) error {
	pgwireKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if pgwireKind != KindAuthentication {
		return unexpectedKind(pgwireKind, KindAuthentication)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthMD5Password {
		return unexpectedAuthKind(authKind, KindAuthMD5Password)
	}
	copy(x.Salt[:], b)
	return nil
}
