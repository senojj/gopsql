package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &AuthenticationCleartextPassword{}
var _ Backend = &AuthenticationCleartextPassword{}

type AuthenticationCleartextPassword struct{}

func (x *AuthenticationCleartextPassword) message() {}

func (x *AuthenticationCleartextPassword) backend() {}

func (x *AuthenticationCleartextPassword) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthClearTextPassword))
	return buf.Bytes(), nil
}

func (x *AuthenticationCleartextPassword) UnmarshalBinary(b []byte) error {
	kind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if kind != byte(MsgAuthentication) {
		return unexpectedKind(kind, byte(MsgAuthentication))
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != int32(AuthClearTextPassword) {
		return unexpectedAuthKind(authKind, int32(AuthClearTextPassword))
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
