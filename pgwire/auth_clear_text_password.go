package pgwire

import (
	"gopsql/pgio"
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

	buf := pgio.NewBuffer(b)
	buf.Grow(size)
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthCleartextPassword)
	return buf.Bytes(), nil
}

func (x *AuthCleartextPassword) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthCleartextPassword {
		return unexpectedAuthKind(authKind, KindAuthCleartextPassword)
	}

	if len(b) > 0 {
		return invalidFormat(pgio.ErrValueOverflow)
	}
	return nil
}
