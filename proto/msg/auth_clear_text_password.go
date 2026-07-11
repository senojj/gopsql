package msg

import (
	"gopsql/internal/bytex"
)

const KindAuthCleartextPassword int32 = 3

var _ Message = &AuthCleartextPassword{}
var _ Backend = &AuthCleartextPassword{}

type AuthCleartextPassword struct{}

func (x *AuthCleartextPassword) message() {}

func (x *AuthCleartextPassword) backend() {}

func (x *AuthCleartextPassword) AppendBinary(b []byte) ([]byte, error) {
	const length = sizeMessageLength + sizeAuthKind
	const size = sizeMessageKind + length

	buf := bytex.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthCleartextPassword)
	return buf.Bytes(), nil
}

func (x *AuthCleartextPassword) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthCleartextPassword {
		return unexpectedAuthKind(authKind, KindAuthCleartextPassword)
	}

	if len(b) > 0 {
		return invalidFormat(bytex.ErrValueOverflow)
	}
	return nil
}
