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
	b, err := ShiftHeader(MsgAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthClearTextPassword.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthClearTextPassword)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
