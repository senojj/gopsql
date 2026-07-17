package pgwire

import (
	"gopsql/pgio"
)

var _ Message = &AuthenticationKerberosV5{}
var _ Backend = &AuthenticationKerberosV5{}

type AuthenticationKerberosV5 struct{}

func (x *AuthenticationKerberosV5) message() {}

func (x *AuthenticationKerberosV5) backend() {}

func (x *AuthenticationKerberosV5) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(byte(MsgAuthentication))
	buf.AppendInt32(int32(length))
	buf.AppendInt32(int32(AuthKerberosV5))
	return buf.Bytes(), nil
}

func (x *AuthenticationKerberosV5) UnmarshalBinary(b []byte) error {
	b, err := ShiftHeader(MsgAuthentication, b)
	if err != nil {
		return invalidFormat(err)
	}

	authKind, b, err := pgio.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if !AuthKerberosV5.Is(authKind) {
		return unexpectedAuthKind(authKind, AuthKerberosV5)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
