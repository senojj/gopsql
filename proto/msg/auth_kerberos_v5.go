package msg

import (
	"gopsql/internal/bx"
	"slices"
)

const KindAuthKerberosV5 int32 = 2

var _ Message = &AuthKerberosV5{}
var _ Backend = &AuthKerberosV5{}

type AuthKerberosV5 struct {
	msg
	back
}

func (x *AuthKerberosV5) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthKerberosV5)
	return b, nil
}

func (x *AuthKerberosV5) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthKerberosV5 {
		return unexpectedAuthKind(authKind, KindAuthKerberosV5)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}
