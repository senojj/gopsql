package msg

import (
	"gopsql/internal/bx"
	"slices"
)

const KindAuthOk int32 = 0

var _ Message = &AuthOk{}
var _ Backend = &AuthOk{}

type AuthOk struct {
	msg
	back
}

func (x *AuthOk) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	b = slices.Grow(b, size)
	b = bx.AppendByte(b, KindAuthentication)
	b = bx.AppendInt32(b, int32(length))
	b = bx.AppendInt32(b, KindAuthOk)
	return b, nil
}

func (x *AuthOk) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthOk {
		return unexpectedAuthKind(authKind, KindAuthOk)
	}

	if len(b) > 0 {
		return bx.ErrValueOverflow
	}
	return nil
}
