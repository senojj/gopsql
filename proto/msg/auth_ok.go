package msg

import (
	"gopsql/internal/bytex"
)

const KindAuthOk int32 = 0

var _ Message = &AuthOk{}
var _ Backend = &AuthOk{}

type AuthOk struct{}

func (x *AuthOk) message() {}

func (x *AuthOk) backend() {}

func (x *AuthOk) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthOk)
	return buf.Bytes(), nil
}

func (x *AuthOk) UnmarshalBinary(b []byte) error {
	msgKind, b, err := ShiftHeader(b)
	if err != nil {
		return invalidFormat(err)
	}

	if msgKind != KindAuthentication {
		return unexpectedKind(msgKind, KindAuthentication)
	}

	authKind, b, err := bytex.ShiftInt32(b)
	if err != nil {
		return invalidFormat(err)
	}

	if authKind != KindAuthOk {
		return unexpectedAuthKind(authKind, KindAuthOk)
	}

	if len(b) > 0 {
		return bytex.ErrValueOverflow
	}
	return nil
}
