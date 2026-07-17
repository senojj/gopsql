package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &AuthenticationSSPI{}
var _ Backend = &AuthenticationSSPI{}

type AuthenticationSSPI struct{}

func (x *AuthenticationSSPI) message() {}

func (x *AuthenticationSSPI) backend() {}

func (x *AuthenticationSSPI) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthSSPI))
	return buf.Bytes(), nil
}

func (x *AuthenticationSSPI) UnmarshalBinary(b []byte) error {
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

	if authKind != int32(AuthSSPI) {
		return unexpectedAuthKind(authKind, int32(AuthSSPI))
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
