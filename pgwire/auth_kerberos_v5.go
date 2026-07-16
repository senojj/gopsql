package pgwire

import (
	"gopsql/pgio"
)

const KindAuthKerberosV5 int32 = 2

var _ Message = &AuthKerberosV5{}
var _ Backend = &AuthKerberosV5{}

type AuthKerberosV5 struct{}

func (x *AuthKerberosV5) message() {}

func (x *AuthKerberosV5) backend() {}

func (x *AuthKerberosV5) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthKerberosV5)
	return buf.Bytes(), nil
}

func (x *AuthKerberosV5) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthKerberosV5 {
		return unexpectedAuthKind(authKind, KindAuthKerberosV5)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
