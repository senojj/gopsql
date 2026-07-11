package msg

import (
	"gopsql/internal/bx"
	"slices"
)

const KindAuthCleartextPassword int32 = 3

var _ Message = &AuthCleartextPassword{}
var _ Backend = &AuthCleartextPassword{}

type AuthCleartextPassword struct {
	msg
	back
}

func (x *AuthCleartextPassword) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthCleartextPassword)
	return b, nil
}

func (x *AuthCleartextPassword) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthCleartextPassword {
		return unexpectedAuthKind(authKind, KindAuthCleartextPassword)
	}

	if len(b) > 0 {
		return invalidFormat(bx.ErrValueOverflow)
	}
	return nil
}
