package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &AuthenticationOk{}
var _ Backend = &AuthenticationOk{}

type AuthenticationOk struct{}

func (x *AuthenticationOk) message() {}

func (x *AuthenticationOk) backend() {}

func (x *AuthenticationOk) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthOk))
	return buf.Bytes(), nil
}

func (x *AuthenticationOk) UnmarshalBinary(b []byte) error {
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

	if authKind != int32(AuthOk) {
		return unexpectedAuthKind(authKind, int32(AuthOk))
	}

	if len(b) > 0 {
		return pgio.ErrValueOverflow
	}
	return nil
}
