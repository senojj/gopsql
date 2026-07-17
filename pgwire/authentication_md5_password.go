package pgwire

import (
	"gopsql/pgio"
)

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
	buf.AppendByte(byte(MsgAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthMD5Password))
	buf.AppendByte(x.Salt[:]...)
	return buf.Bytes(), nil
}

func (x *AuthenticationMD5Password) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthMD5Password.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthMD5Password)
	}
	copy(x.Salt[:], b)
	return nil
}
