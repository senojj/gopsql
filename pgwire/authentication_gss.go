package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &AuthenticationGSS{}
var _ Backend = &AuthenticationGSS{}

type AuthenticationGSS struct{}

func (x *AuthenticationGSS) message() {}

func (x *AuthenticationGSS) backend() {}

func (x *AuthenticationGSS) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthGSS))
	return buf.Bytes(), nil
}

func (x *AuthenticationGSS) UnmarshalBinary(b []byte) error {
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

	if authKind != int32(AuthGSS) {
		return unexpectedAuthKind(authKind, int32(AuthGSS))
	}
	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
