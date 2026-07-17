package pgwire

import (
	"gopsql/pgio"
)

const KindAuthOk int32 = 0

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
	buf.AppendByte(KindAuthentication)
	buf.AppendInt32(int32(length))
	buf.AppendInt32(KindAuthOk)
	return buf.Bytes(), nil
}

func (x *AuthenticationOk) UnmarshalBinary(b []byte) error {
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

	if authKind != KindAuthOk {
		return unexpectedAuthKind(authKind, KindAuthOk)
	}

	if len(b) > 0 {
		return pgio.ErrValueOverflow
	}
	return nil
}
